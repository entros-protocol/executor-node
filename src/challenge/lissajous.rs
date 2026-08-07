use serde::{Deserialize, Serialize};

/// Server-issued Lissajous curve parameters for the touch challenge.
/// Drawn by the user on the client UI and validated against server-issued nonce data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LissajousParams {
    pub a: u8,
    pub b: u8,
    pub delta: f64,
    pub points: u16,
    pub anchor_x: u16,
    pub anchor_y: u16,
}

impl LissajousParams {
    /// Generate random server-issued Lissajous parameters.
    pub fn generate() -> Self {
        let ratios: [(u8, u8); 5] = [(1, 2), (2, 3), (3, 4), (3, 5), (4, 5)];
        let anchors: [(u16, u16); 5] = [(0, 0), (100, 0), (0, 100), (100, 100), (50, 50)];

        let r_idx: usize = rand::random::<usize>() % ratios.len();
        let a_idx: usize = rand::random::<usize>() % anchors.len();
        let rand_f: f64 = rand::random::<f64>();
        let delta = std::f64::consts::PI * (0.25 + rand_f * 0.5);

        let (a, b) = ratios[r_idx];
        let (anchor_x, anchor_y) = anchors[a_idx];

        Self {
            a,
            b,
            delta,
            points: 200,
            anchor_x,
            anchor_y,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_returns_valid_params() {
        let params = LissajousParams::generate();
        assert!(params.a >= 1 && params.a <= 4);
        assert!(params.b >= 2 && params.b <= 5);
        assert!(params.points == 200);
        assert!(params.delta >= std::f64::consts::PI * 0.25);
        assert!(params.delta <= std::f64::consts::PI * 0.75);
    }
}
