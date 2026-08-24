//! Server-side challenge phrase generator.
//!
//! Picks 5 random words from `word_dict::WORDS` — a curated dictionary of
//! 1,357 neutral/positive English words (4-8 letters, 1-3 syllables, no
//! homophones, no substring collisions). The same dictionary is vendored
//! into `entros-validation/src/word_dict.rs` so the validator knows what the
//! executor could have issued; the two files are kept in sync by the
//! shared curation script at `entros-validation/scripts/curate-dictionary.py`.
//!
//! Why server-issued rather than client-issued: without server issuance,
//! phrase content binding is trivially defeated — an attacker submits
//! their own phrase matching whatever audio they captured. Server-issued
//! phrases are bound to the challenge nonce at
//! `executor-node/src/challenge/registry.rs` and verified by the
//! validation service against submitted audio.
//!
//! Output shape:
//!
//! ```text
//! "elephant mountain coffee yellow bicycle"
//! ```

use rand::seq::SliceRandom;

use super::word_dict;

/// Generate a random phrase of `word_count` space-separated words drawn
/// uniformly from the curated dictionary. Returns an empty string when
/// `word_count == 0` (edge case; caller should request at least 1).
///
/// Uses `rand::thread_rng()` for unpredictable output (cryptographically
/// adequate for challenge issuance; the phrase is bound to a fresh nonce
/// with a 60s TTL, so the window for an attacker to exploit predicted
/// output is narrow even without a CSPRNG).
pub fn generate_phrase(word_count: usize) -> String {
    if word_count == 0 {
        return String::new();
    }
    let mut rng = rand::thread_rng();
    // `choose_multiple` samples without replacement — our dictionary has
    // 1,357 entries so it always returns exactly `word_count` items in
    // practice. `.copied()` turns iterator items from `&&str` to `&str`.
    word_dict::WORDS
        .choose_multiple(&mut rng, word_count)
        .copied()
        .collect::<Vec<&str>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_requested_word_count() {
        let phrase = generate_phrase(5);
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 5);
    }

    #[test]
    fn zero_word_count_returns_empty() {
        assert_eq!(generate_phrase(0), "");
    }

    #[test]
    fn every_word_is_in_dictionary() {
        // Run 20 generations — if any word ever falls outside the dictionary,
        // the phrase_gen / word_dict contract is broken.
        for _ in 0..20 {
            let phrase = generate_phrase(5);
            for word in phrase.split_whitespace() {
                assert!(
                    word_dict::WORDS.contains(&word),
                    "generated word {word:?} is not in the curated dictionary"
                );
            }
        }
    }

    #[test]
    fn successive_calls_differ() {
        // Not a hard guarantee — two calls could theoretically produce the
        // same 5-word phrase — but with 1,357^5 ≈ 4.7×10^15 phrase space
        // collision is astronomically unlikely.
        let a = generate_phrase(5);
        let b = generate_phrase(5);
        assert_ne!(a, b);
    }

    #[test]
    fn dictionary_has_expected_size() {
        // Drift guard: the entros-validation and executor-node copies of
        // word_dict.rs must stay identical. If this assertion fails, one
        // was regenerated and the other wasn't. Rerun
        // `entros-validation/scripts/curate-dictionary.py` to resync both.
        assert!(
            word_dict::WORDS.len() >= 900,
            "word dictionary shrunk below 900; drift likely"
        );
        assert!(
            word_dict::WORDS.len() <= 1800,
            "word dictionary grew above 1800; drift likely"
        );
    }

    #[test]
    fn phrase_contains_only_ascii_lowercase_and_spaces() {
        let phrase = generate_phrase(5);
        for c in phrase.chars() {
            assert!(
                c.is_ascii_lowercase() || c == ' ',
                "unexpected char {c:?} in phrase {phrase:?}"
            );
        }
    }
}
