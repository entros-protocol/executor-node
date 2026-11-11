//! Bounds the paired finalize bodies held at once, in total and per client network.
//!
//! Both places are taken before the body is read. The total place is kept until the finalize
//! handler returns, so the bodies in memory never exceed `SESSION_UPLOADS` times the finalize
//! body limit. The network place is returned once the body has been read, so a client
//! network holds at most `SESSION_UPLOADS_PER_NETWORK` uploads in progress. One network that
//! uploads slowly cannot take every place, and clients that share an address do not wait on
//! each other's processing.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use futures_util::{Stream, StreamExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Finalize bodies uploading or held at once, across every network.
pub const SESSION_UPLOADS: usize = 64;
/// Finalize bodies one client network may upload at once.
pub const SESSION_UPLOADS_PER_NETWORK: usize = 2;
/// How long a finalize waits for a place before it is refused. Nothing is read while it
/// waits, so a waiting request holds a connection and no buffered bytes.
pub const UPLOAD_WAIT: Duration = Duration::from_secs(2);

/// One network's places, and how many requests hold or await one of them.
struct NetworkPlaces {
    places: Arc<Semaphore>,
    users: usize,
}

pub struct UploadGate {
    total: Arc<Semaphore>,
    per_network: usize,
    networks: Mutex<HashMap<IpAddr, NetworkPlaces>>,
}

impl UploadGate {
    pub fn new(total: usize, per_network: usize) -> Arc<Self> {
        Arc::new(Self {
            total: Arc::new(Semaphore::new(total)),
            per_network,
            networks: Mutex::new(HashMap::new()),
        })
    }

    /// Admits one upload, or `None` once no place frees within `UPLOAD_WAIT`. A request
    /// whose client network did not resolve is bound by the total alone.
    pub async fn admit(self: &Arc<Self>, network: Option<IpAddr>) -> Option<Admission> {
        tokio::time::timeout(UPLOAD_WAIT, self.acquire(network))
            .await
            .ok()
            .flatten()
    }

    /// The network place comes first, so a network at its bound waits without holding
    /// one of the shared places.
    async fn acquire(self: &Arc<Self>, network: Option<IpAddr>) -> Option<Admission> {
        let network = match network {
            Some(network) => {
                let (places, user) = self.join(network);
                Some(NetworkPlace {
                    _permit: places.acquire_owned().await.ok()?,
                    _user: user,
                })
            }
            None => None,
        };
        let total = Arc::clone(&self.total).acquire_owned().await.ok()?;
        Some(Admission {
            pass: UploadPass {
                _total: Arc::new(total),
            },
            network,
        })
    }

    fn join(self: &Arc<Self>, network: IpAddr) -> (Arc<Semaphore>, NetworkUser) {
        let mut networks = self.networks();
        let entry = networks.entry(network).or_insert_with(|| NetworkPlaces {
            places: Arc::new(Semaphore::new(self.per_network)),
            users: 0,
        });
        entry.users += 1;
        (
            Arc::clone(&entry.places),
            NetworkUser {
                gate: Arc::clone(self),
                network,
            },
        )
    }

    /// The map holds no invariant a panicking holder could break midway, so a poisoned
    /// lock is still sound to use.
    fn networks(&self) -> MutexGuard<'_, HashMap<IpAddr, NetworkPlaces>> {
        self.networks.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    fn tracked_networks(&self) -> usize {
        self.networks().len()
    }
}

/// Counts one request against its network's entry while it holds or awaits a place, and
/// removes the entry with the last one, whether it was admitted or gave up waiting.
struct NetworkUser {
    gate: Arc<UploadGate>,
    network: IpAddr,
}

impl Drop for NetworkUser {
    fn drop(&mut self) {
        let mut networks = self.gate.networks();
        if let Some(entry) = networks.get_mut(&self.network) {
            entry.users = entry.users.saturating_sub(1);
            if entry.users == 0 {
                networks.remove(&self.network);
            }
        }
    }
}

/// One network place. Fields drop in order: the place is returned before the entry can be
/// removed, so a new entry for the network never starts beside places still held on the old
/// one.
pub struct NetworkPlace {
    _permit: OwnedSemaphorePermit,
    _user: NetworkUser,
}

/// The total place of one admitted upload. It travels with the request, and the finalize
/// handler holds a copy until it returns, so the parsed body is covered and the timing floor
/// after it is not.
#[derive(Clone)]
pub struct UploadPass {
    _total: Arc<OwnedSemaphorePermit>,
}

/// The places one admitted upload holds.
pub struct Admission {
    pub pass: UploadPass,
    /// `None` when the client network did not resolve.
    pub network: Option<NetworkPlace>,
}

impl Admission {
    /// The request with its pass attached, and with a body that returns the network place
    /// once it has been read to the end. A body that is dropped unread returns it then.
    pub fn attach(self, request: Request) -> Request {
        let (mut parts, body) = request.into_parts();
        parts.extensions.insert(self.pass);
        let body = match self.network {
            Some(place) => Body::from_stream(release_when_read(body.into_data_stream(), place)),
            None => body,
        };
        Request::from_parts(parts, body)
    }
}

/// Yields `stream` unchanged and drops `place` when the stream ends.
fn release_when_read<S>(stream: S, place: NetworkPlace) -> impl Stream<Item = S::Item>
where
    S: Stream + Unpin,
{
    futures_util::stream::unfold(Some((stream, place)), |state| async move {
        let (mut stream, place) = state?;
        let item = stream.next().await?;
        Some((item, Some((stream, place))))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7));
    const AWAY: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 44));

    #[tokio::test(start_paused = true)]
    async fn a_network_holds_at_most_its_bound() {
        let gate = UploadGate::new(8, 2);
        let first = gate.admit(Some(HOME)).await.expect("first place");
        let _second = gate.admit(Some(HOME)).await.expect("second place");
        assert!(gate.admit(Some(HOME)).await.is_none());
        assert!(gate.admit(Some(AWAY)).await.is_some());

        drop(first);
        assert!(gate.admit(Some(HOME)).await.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn the_total_binds_every_network() {
        let gate = UploadGate::new(2, 2);
        let _home = gate.admit(Some(HOME)).await.expect("place");
        let _away = gate.admit(Some(AWAY)).await.expect("place");
        assert!(gate.admit(None).await.is_none());
        assert!(gate
            .admit(Some("203.0.113.1".parse().expect("address")))
            .await
            .is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn an_unresolved_network_skips_the_network_bound() {
        let gate = UploadGate::new(8, 1);
        let _first = gate.admit(None).await.expect("place");
        let _second = gate.admit(None).await.expect("place");
        assert_eq!(gate.tracked_networks(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_waiting_upload_takes_the_next_free_place() {
        let gate = UploadGate::new(8, 1);
        let held = gate.admit(Some(HOME)).await.expect("place");
        let waiter = {
            let gate = Arc::clone(&gate);
            tokio::spawn(async move { gate.admit(Some(HOME)).await.is_some() })
        };
        tokio::time::sleep(UPLOAD_WAIT / 2).await;
        drop(held);
        assert!(waiter.await.expect("task"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_wait_ends_at_its_deadline() {
        let gate = UploadGate::new(8, 1);
        let _held = gate.admit(Some(HOME)).await.expect("place");
        let started = tokio::time::Instant::now();
        assert!(gate.admit(Some(HOME)).await.is_none());
        assert_eq!(started.elapsed(), UPLOAD_WAIT);
    }

    fn request_with(body: Body) -> Request {
        Request::new(body)
    }

    /// A finished upload returns its network place and keeps its total place for as long as
    /// a copy of its pass is held.
    #[tokio::test(start_paused = true)]
    async fn a_read_body_returns_its_network_place_and_keeps_the_total() {
        let gate = UploadGate::new(2, 1);
        let request = gate
            .admit(Some(HOME))
            .await
            .expect("place")
            .attach(request_with(Body::from("finished upload")));
        let pass = request
            .extensions()
            .get::<UploadPass>()
            .cloned()
            .expect("the pass travels with the request");
        let (_, body) = request.into_parts();
        let bytes = axum::body::to_bytes(body, 1_024).await.expect("body");
        assert_eq!(&bytes[..], b"finished upload");

        let second = gate
            .admit(Some(HOME))
            .await
            .expect("the network place is free");
        assert!(
            gate.admit(Some(AWAY)).await.is_none(),
            "the total still binds"
        );
        drop(pass);
        assert!(gate.admit(Some(AWAY)).await.is_some());
        drop(second);
    }

    #[tokio::test(start_paused = true)]
    async fn an_upload_in_progress_keeps_its_network_place() {
        let gate = UploadGate::new(4, 1);
        let (sender, receiver) = tokio::sync::mpsc::channel::<&'static [u8]>(1);
        let chunks = futures_util::stream::unfold(receiver, |mut receiver| async move {
            let chunk = receiver.recv().await?;
            Some((Ok::<_, std::convert::Infallible>(chunk), receiver))
        });
        let request = gate
            .admit(Some(HOME))
            .await
            .expect("place")
            .attach(request_with(Body::from_stream(chunks)));
        let mut body = request.into_body().into_data_stream();

        sender.send(b"part").await.expect("send");
        assert!(body.next().await.is_some());
        assert!(gate.admit(Some(HOME)).await.is_none());

        drop(sender);
        assert!(body.next().await.is_none());
        assert!(gate.admit(Some(HOME)).await.is_some());
    }

    /// Entries are dropped with their last holder or waiter, so the map never grows with
    /// networks that have gone.
    #[tokio::test(start_paused = true)]
    async fn a_network_with_no_holder_or_waiter_leaves_no_entry() {
        let gate = UploadGate::new(8, 1);
        let held = gate.admit(Some(HOME)).await.expect("place");
        assert!(gate.admit(Some(HOME)).await.is_none());
        assert_eq!(gate.tracked_networks(), 1);
        let Admission { pass, network } = held;
        let copy = pass.clone();
        drop(pass);
        assert_eq!(gate.tracked_networks(), 1);
        drop(network);
        assert_eq!(gate.tracked_networks(), 0);
        drop(copy);

        // A waiter whose client went away mid-wait leaves nothing behind either.
        let held = gate.admit(Some(AWAY)).await.expect("place");
        let waiter = {
            let gate = Arc::clone(&gate);
            tokio::spawn(async move { gate.admit(Some(AWAY)).await.is_some() })
        };
        tokio::time::sleep(UPLOAD_WAIT / 2).await;
        waiter.abort();
        assert!(waiter.await.is_err());
        assert_eq!(gate.tracked_networks(), 1);
        drop(held);
        assert_eq!(gate.tracked_networks(), 0);
    }
}
