//! Curated real-word dictionary for phrase content binding (#89 v3).
//!
//! **Source of truth: `entros-validation/src/word_dict.rs`.** This is a
//! verbatim vendored copy. If this file diverges from the entros-validation
//! copy, the validation service will reject phrases that reference words
//! it doesn't know. Regenerate both files simultaneously from the single
//! curation script at `entros-validation/scripts/curate-dictionary.py`.
//!
//! Drift-detection lives in the tests at the bottom of this file — if they
//! fail, the two copies are out of sync.

/// 1240 words, alphabetically sorted.
pub const WORDS: &[&str] = &[
    "able", "about", "above", "absolute", "accept", "access", "account", "accurate", "achieve",
    "across", "acting", "action", "active", "actor", "acts", "actual", "added", "adding",
    "addition", "address", "admit", "adopted", "adult", "advance", "advice", "affairs", "affect",
    "afford", "after", "again", "aged", "agencies", "agency", "agent", "ages", "agree", "ahead",
    "aircraft", "airport", "album", "alive", "almost", "along", "already", "also", "although",
    "always", "amazing", "among", "amount", "ancient", "animal", "annual", "another", "answer",
    "anymore", "anyone", "anything", "anyway", "anywhere", "apart", "appeal", "appear", "apply",
    "approach", "approval", "approved", "area", "around", "arrived", "article", "artist", "aside",
    "asking", "aspects", "assembly", "assets", "assume", "attached", "attempt", "attend",
    "attitude", "attorney", "audience", "author", "average", "award", "aware", "away", "awesome",
    "baby", "back", "balance", "band", "base", "baseball", "basic", "basis", "bathroom", "battery",
    "beach", "beauty", "became", "because", "become", "becoming", "before", "began", "begin",
    "behavior", "behind", "being", "believe", "bell", "below", "benefit", "besides", "best",
    "better", "between", "beyond", "bigger", "biggest", "bike", "bill", "billion", "bird", "birth",
    "birthday", "blog", "blow", "blue", "body", "bond", "book", "born", "boss", "both", "bottom",
    "boys", "brain", "branch", "brand", "bread", "break", "breath", "bridge", "brief", "bright",
    "bring", "broad", "brother", "brought", "brown", "build", "building", "bunch", "business",
    "busy", "button", "buying", "cake", "calling", "camera", "camp", "cannot", "capable",
    "captain", "carbon", "care", "careful", "carry", "carrying", "case", "cash", "catch", "causes",
    "causing", "cells", "center", "central", "century", "certain", "chain", "chair", "champion",
    "chance", "change", "changing", "chapter", "charge", "chat", "check", "cheese", "chest",
    "chicken", "chief", "child", "children", "choice", "choose", "chose", "circle", "city",
    "claim", "class", "clean", "clear", "click", "client", "close", "clothes", "club", "coach",
    "coast", "code", "coffee", "college", "color", "combined", "comedy", "comes", "command",
    "common", "company", "compared", "complete", "complex", "computer", "concept", "concern",
    "concert", "conduct", "consider", "constant", "consumer", "contain", "content", "context",
    "continue", "contract", "control", "cook", "cool", "copy", "corner", "correct", "cost",
    "could", "council", "counter", "country", "county", "couple", "course", "cover", "coverage",
    "cream", "create", "creating", "creation", "creative", "credit", "crew", "crowd", "crown",
    "culture", "current", "customer", "cute", "cycle", "daily", "dance", "dancing", "data", "date",
    "dating", "daughter", "days", "deal", "dealing", "dear", "debut", "decade", "decide",
    "decision", "declared", "deep", "defense", "degree", "deliver", "depends", "deputy",
    "describe", "deserve", "design", "desire", "despite", "detail", "develop", "device", "diet",
    "digital", "dinner", "direct", "discuss", "display", "distance", "district", "division",
    "document", "does", "dogs", "doing", "dollar", "domestic", "done", "door", "double", "down",
    "download", "draft", "drama", "draw", "drawing", "drive", "driving", "dropped", "during",
    "duty", "earlier", "early", "earned", "easier", "easily", "east", "eastern", "easy", "edge",
    "editor", "effect", "effort", "eggs", "eight", "either", "elected", "electric", "elements",
    "else", "email", "employee", "ended", "ending", "ends", "energy", "engaged", "engine", "enjoy",
    "enough", "ensure", "entered", "entire", "entitled", "entry", "episode", "equal", "estate",
    "even", "evening", "ever", "everyone", "evidence", "exact", "example", "except", "excited",
    "exciting", "excuse", "exercise", "exist", "existing", "expect", "expert", "explain",
    "express", "extended", "external", "extra", "extreme", "eyes", "face", "facing", "fact",
    "fair", "fall", "familiar", "family", "famous", "fans", "fantasy", "fashion", "fast", "father",
    "favor", "favorite", "feature", "feed", "feel", "feeling", "fees", "feet", "fell", "felt",
    "festival", "field", "figure", "file", "film", "final", "finance", "find", "finding", "fine",
    "fingers", "finish", "firm", "first", "fish", "five", "fixed", "flat", "flight", "flow",
    "flowers", "flying", "focus", "folks", "follow", "food", "foot", "football", "foreign",
    "forest", "form", "forward", "found", "four", "frame", "free", "freedom", "fresh", "friend",
    "from", "front", "fruit", "fuel", "full", "function", "fund", "funding", "funny", "further",
    "future", "game", "garden", "gave", "general", "gets", "getting", "giant", "gift", "girl",
    "give", "giving", "glad", "global", "goes", "going", "gold", "golf", "gone", "good", "grade",
    "graduate", "grant", "great", "greatest", "green", "grew", "ground", "group", "grow",
    "growing", "guess", "guest", "guys", "hand", "happen", "happy", "harder", "hardly", "have",
    "having", "headed", "heads", "health", "hearing", "heat", "heavily", "heavy", "held", "hello",
    "helping", "here", "herself", "hidden", "high", "highest", "hill", "himself", "history",
    "hits", "holding", "holiday", "home", "honest", "honor", "hoping", "hotel", "hour", "house",
    "housing", "however", "huge", "human", "hundred", "husband", "idea", "image", "imagine",
    "impact", "improve", "include", "income", "increase", "indeed", "index", "industry", "info",
    "initial", "inside", "inspired", "instance", "instead", "intended", "interest", "internal",
    "internet", "into", "invited", "involved", "iron", "island", "issue", "item", "itself", "jobs",
    "join", "joke", "journal", "journey", "jump", "just", "justice", "keep", "keeping", "kids",
    "kind", "kitchen", "knew", "know", "knowing", "labor", "lady", "laid", "lake", "lane",
    "language", "large", "last", "late", "latter", "laughing", "launch", "laws", "lawyer", "lead",
    "leaders", "league", "learn", "learning", "leaves", "leaving", "left", "legal", "legs", "less",
    "lets", "letter", "letting", "level", "library", "license", "life", "lights", "limit", "line",
    "link", "list", "little", "lived", "lives", "living", "load", "local", "located", "location",
    "lock", "longer", "look", "lots", "loud", "love", "luck", "lunch", "machine", "made",
    "magazine", "magic", "main", "maintain", "major", "manage", "manner", "many", "market",
    "marriage", "married", "mass", "massive", "master", "match", "mate", "matters", "maximum",
    "maybe", "meant", "measure", "media", "medical", "medium", "meet", "meeting", "member",
    "memory", "mention", "message", "metal", "method", "middle", "might", "mile", "milk",
    "million", "mind", "mine", "minimum", "mining", "minor", "minute", "mission", "mobile", "mode",
    "moment", "money", "month", "moon", "more", "morning", "mostly", "mother", "motion", "motor",
    "mountain", "mouth", "movement", "movie", "moving", "much", "multi", "multiple", "museum",
    "music", "must", "myself", "name", "national", "native", "natural", "nature", "near", "need",
    "network", "news", "next", "nice", "night", "nine", "noise", "none", "normal", "north",
    "northern", "note", "nothing", "notice", "novel", "number", "numerous", "object", "obvious",
    "occurred", "ocean", "offer", "offering", "office", "official", "often", "okay", "older",
    "once", "only", "onto", "open", "opinion", "opposed", "opposite", "option", "orange", "order",
    "origin", "others", "outside", "overall", "owner", "pack", "page", "paid", "paint", "painting",
    "pair", "panel", "paper", "parent", "partner", "party", "pass", "passing", "past", "path",
    "pattern", "paying", "payment", "peak", "people", "percent", "perfect", "perform", "perhaps",
    "period", "person", "phase", "phone", "photo", "physical", "pick", "picture", "piece", "pilot",
    "pink", "place", "plan", "planning", "plastic", "platform", "play", "players", "playing",
    "pleasure", "plenty", "plot", "plus", "point", "pool", "popular", "port", "portion",
    "position", "positive", "possible", "possibly", "post", "pounds", "power", "powerful",
    "practice", "premier", "prepare", "presence", "present", "pretty", "prevent", "previous",
    "price", "prime", "print", "prior", "private", "prize", "probably", "process", "produce",
    "product", "profile", "profit", "program", "progress", "project", "promise", "promote",
    "proper", "proposed", "protect", "protein", "proud", "provide", "purchase", "pure", "purpose",
    "push", "puts", "putting", "quality", "quarter", "queen", "question", "quick", "quiet", "quit",
    "quote", "radio", "raise", "random", "rare", "rate", "rather", "reach", "reading", "real",
    "realize", "reason", "receive", "recent", "record", "recovery", "reduce", "referred", "region",
    "register", "regular", "related", "release", "relevant", "relief", "remained", "remains",
    "replaced", "reported", "reports", "request", "require", "research", "reserve", "respect",
    "respond", "response", "result", "retail", "return", "revealed", "revenue", "review", "ride",
    "rights", "rise", "rising", "river", "roads", "rock", "room", "route", "rule", "running",
    "runs", "rural", "safe", "said", "sale", "same", "sample", "save", "saving", "says", "scale",
    "scenes", "schedule", "scheme", "school", "science", "screen", "season", "seat", "second",
    "secret", "section", "sector", "secure", "seeing", "seek", "seeking", "seem", "seen", "sees",
    "sell", "selling", "semi", "send", "senior", "sense", "sentence", "separate", "series",
    "served", "service", "serving", "session", "setting", "several", "shape", "share", "sharing",
    "shift", "ship", "shipping", "shoes", "shop", "shopping", "short", "should", "show", "shut",
    "signal", "signed", "silver", "similar", "simple", "simply", "since", "singer", "singing",
    "single", "sister", "site", "sitting", "size", "skills", "sleep", "sleeping", "slightly",
    "slow", "small", "smart", "snow", "social", "soft", "software", "solar", "sold", "solid",
    "solo", "solution", "some", "somebody", "somehow", "someone", "somewhat", "song", "soon",
    "sort", "sound", "source", "south", "southern", "space", "speaking", "special", "species",
    "specific", "speech", "speed", "spend", "split", "spoke", "spot", "spread", "spring", "squad",
    "square", "stadium", "stage", "stand", "standard", "standing", "started", "starting",
    "station", "status", "stay", "staying", "steam", "steel", "stick", "still", "stock", "stone",
    "stood", "storage", "store", "stories", "strategy", "stream", "street", "strength", "strong",
    "student", "studio", "study", "stuff", "style", "subject", "success", "suddenly", "sugar",
    "suggest", "suit", "summer", "super", "supply", "support", "suppose", "surely", "surface",
    "surprise", "survey", "sweet", "switch", "system", "take", "talent", "talking", "tall", "tank",
    "task", "taste", "taxes", "teach", "teachers", "teaching", "teams", "tech", "teeth", "tell",
    "term", "test", "testing", "text", "that", "theatre", "their", "them", "then", "theory",
    "therapy", "these", "they", "things", "thinking", "third", "this", "those", "thousand",
    "three", "through", "ticket", "tight", "time", "tiny", "tips", "title", "today", "together",
    "told", "tomorrow", "total", "touch", "tour", "toward", "town", "track", "trade", "trading",
    "traffic", "train", "training", "transfer", "travel", "treat", "trees", "trend", "tried",
    "tries", "trip", "truck", "true", "truly", "trust", "truth", "trying", "turned", "turning",
    "turns", "twenty", "twice", "type", "typical", "ultimate", "under", "union", "unique", "unit",
    "universe", "unknown", "unlike", "until", "updated", "upon", "urban", "useful", "user",
    "usual", "valuable", "value", "various", "vehicle", "version", "very", "victory", "views",
    "village", "visit", "voice", "volume", "wait", "waiting", "walk", "walking", "want", "warm",
    "water", "wave", "wearing", "website", "wedding", "week", "weekend", "well", "west", "western",
    "what", "whatever", "when", "whenever", "which", "while", "whose", "wide", "wife", "wild",
    "will", "wind", "windows", "wing", "winner", "winning", "wins", "winter", "wise", "wish",
    "with", "without", "witness", "women", "wonder", "work", "workers", "working", "world",
    "worth", "writer", "writing", "written", "wrote", "yard", "year", "yellow", "young",
    "yourself", "youth", "zero", "zone",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_count_matches_expected() {
        assert_eq!(WORDS.len(), 1240);
    }

    #[test]
    fn first_word_is_stable() {
        assert_eq!(WORDS[0], "able");
    }

    #[test]
    fn last_word_is_stable() {
        assert_eq!(WORDS[WORDS.len() - 1], "zone");
    }

    #[test]
    fn all_lowercase_ascii_alphabetic() {
        for w in WORDS {
            assert!(!w.is_empty(), "empty word in dictionary");
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase()),
                "non-ascii-lowercase word: {w}",
            );
        }
    }

    #[test]
    fn sorted_ascending_with_no_duplicates() {
        for pair in WORDS.windows(2) {
            assert!(
                pair[0] < pair[1],
                "not sorted or duplicate: {} vs {}",
                pair[0],
                pair[1],
            );
        }
    }

    #[test]
    fn word_lengths_in_range() {
        for w in WORDS {
            let n = w.len();
            assert!(
                (4..=8).contains(&n),
                "word {w} has length {n}, expected 4..=8"
            );
        }
    }
}
