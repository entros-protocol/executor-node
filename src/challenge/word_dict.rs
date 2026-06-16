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

/// 1357 words, alphabetically sorted.
pub const WORDS: &[&str] = &[
    "able", "about", "above", "absolute", "accept", "access", "account", "accurate", "achieve",
    "across", "acting", "action", "active", "actor", "acts", "actual", "added", "adding",
    "addition", "address", "admit", "adopted", "adult", "advance", "advice", "affairs", "affect",
    "afford", "after", "again", "aged", "agencies", "agency", "agent", "ages", "agree", "ahead",
    "aircraft", "airport", "album", "alive", "allow", "allowing", "almost", "along", "already",
    "also", "although", "always", "amazing", "among", "amount", "ancient", "animal", "annual",
    "another", "answer", "anymore", "anyone", "anything", "anyway", "anywhere", "apart", "appeal",
    "appear", "applied", "apply", "approach", "approval", "approved", "area", "around", "arrived",
    "article", "artist", "arts", "aside", "asked", "asking", "aspects", "assembly", "assets",
    "assume", "attached", "attempt", "attend", "attitude", "attorney", "audience", "author",
    "average", "award", "aware", "away", "awesome", "baby", "back", "balance", "ball", "band",
    "bank", "base", "baseball", "basic", "basis", "bathroom", "battery", "beach", "bear", "beauty",
    "became", "because", "become", "becoming", "been", "before", "began", "begin", "behavior",
    "behind", "being", "believe", "bell", "below", "benefit", "besides", "best", "better",
    "between", "beyond", "bigger", "biggest", "bike", "bill", "billion", "bird", "birth",
    "birthday", "blog", "blow", "blue", "board", "boat", "bodies", "body", "bond", "book", "born",
    "boss", "both", "bottle", "bottom", "bought", "bowl", "boys", "brain", "branch", "brand",
    "bread", "break", "breaking", "breath", "bridge", "brief", "bright", "bring", "bringing",
    "broad", "brother", "brought", "brown", "build", "building", "built", "bunch", "business",
    "busy", "button", "buying", "cake", "call", "calling", "calm", "camera", "camp", "cannot",
    "capable", "captain", "carbon", "card", "care", "careful", "carried", "carry", "carrying",
    "cars", "case", "cash", "catch", "caught", "caused", "causes", "causing", "cells", "center",
    "central", "century", "certain", "chain", "chair", "champion", "chance", "change", "changing",
    "chapter", "charge", "chat", "check", "cheese", "chest", "chicken", "chief", "child",
    "children", "choice", "choose", "chose", "circle", "cities", "city", "claim", "class", "clean",
    "clear", "click", "client", "close", "clothes", "club", "coach", "coast", "code", "coffee",
    "college", "color", "combined", "comedy", "comes", "command", "common", "company", "compared",
    "complete", "complex", "computer", "concept", "concern", "concert", "conduct", "consider",
    "constant", "consumer", "contact", "contain", "content", "contest", "context", "continue",
    "contract", "control", "cook", "cool", "copy", "core", "corner", "correct", "cost", "could",
    "council", "counter", "country", "county", "couple", "course", "cover", "coverage", "cream",
    "create", "creating", "creation", "creative", "credit", "crew", "crowd", "crown", "cultural",
    "culture", "current", "customer", "cute", "cycle", "daily", "dance", "dancing", "data", "date",
    "dating", "daughter", "days", "deal", "dealing", "dear", "debut", "decade", "decide",
    "decision", "declared", "deep", "defense", "defined", "degree", "deliver", "depends", "depth",
    "deputy", "describe", "deserve", "design", "desire", "despite", "detail", "develop", "device",
    "diet", "digital", "dinner", "direct", "discuss", "display", "distance", "district",
    "division", "document", "does", "dogs", "doing", "dollar", "domestic", "done", "door",
    "double", "down", "download", "draft", "drama", "draw", "drawing", "dream", "drive", "driving",
    "dropped", "during", "duty", "earlier", "early", "earned", "earth", "easier", "easily", "east",
    "eastern", "easy", "edge", "editor", "effect", "effort", "eggs", "eight", "either", "elected",
    "electric", "elements", "else", "email", "employee", "ended", "ending", "ends", "energy",
    "engaged", "engine", "enjoy", "enough", "ensure", "entered", "entire", "entitled", "entry",
    "episode", "equal", "estate", "even", "evening", "ever", "everyone", "evidence", "exact",
    "example", "except", "excited", "exciting", "excuse", "exercise", "exist", "existing",
    "expect", "expert", "explain", "express", "extended", "external", "extra", "extreme", "eyes",
    "face", "facing", "fact", "fair", "fall", "familiar", "families", "family", "famous", "fans",
    "fantasy", "farm", "fashion", "fast", "father", "favor", "favorite", "feature", "feed", "feel",
    "feeling", "fees", "feet", "fell", "felt", "festival", "field", "fifth", "figure", "file",
    "fill", "film", "final", "finance", "find", "finding", "fine", "fingers", "finish", "firm",
    "first", "fish", "five", "fixed", "flat", "flight", "floor", "flow", "flowers", "flying",
    "focus", "folks", "follow", "food", "foot", "football", "foreign", "forest", "forever",
    "forgot", "form", "forward", "found", "four", "frame", "free", "freedom", "fresh", "friend",
    "from", "front", "fruit", "fuel", "full", "function", "fund", "funding", "funny", "further",
    "future", "game", "garden", "gave", "general", "gets", "getting", "giant", "gift", "girl",
    "give", "giving", "glad", "glass", "global", "goal", "goes", "going", "gold", "golf", "gone",
    "good", "grab", "grade", "graduate", "grand", "grant", "great", "greatest", "green", "grew",
    "ground", "group", "grow", "growing", "guard", "guess", "guest", "guide", "guys", "half",
    "hall", "hand", "happen", "happy", "harder", "hardly", "have", "having", "headed", "heads",
    "health", "heard", "hearing", "heart", "heat", "heavily", "heavy", "held", "hello", "help",
    "helping", "here", "hero", "herself", "hidden", "high", "highest", "hill", "himself",
    "history", "hits", "hold", "holding", "holiday", "home", "honest", "honor", "hope", "hoping",
    "horse", "host", "hotel", "hour", "house", "housing", "however", "huge", "human", "hundred",
    "husband", "idea", "image", "imagine", "impact", "improve", "include", "income", "increase",
    "indeed", "index", "industry", "info", "initial", "inside", "inspired", "instance", "instead",
    "intended", "interest", "internal", "internet", "into", "invited", "involved", "iron",
    "island", "issue", "item", "itself", "jobs", "join", "joke", "journal", "journey", "jump",
    "just", "justice", "keep", "keeping", "kept", "kick", "kids", "kind", "kiss", "kitchen",
    "knew", "know", "knowing", "labor", "ladies", "lady", "laid", "lake", "lane", "language",
    "large", "last", "late", "latter", "laugh", "laughing", "launch", "laws", "lawyer", "lead",
    "leaders", "leading", "league", "learn", "learning", "leaves", "leaving", "left", "legal",
    "legs", "length", "less", "lets", "letter", "letting", "level", "library", "license", "life",
    "lights", "limit", "line", "link", "list", "little", "lived", "lives", "living", "load",
    "local", "located", "location", "lock", "longer", "look", "looking", "lots", "loud", "love",
    "luck", "lunch", "machine", "made", "magazine", "magic", "main", "maintain", "major", "make",
    "making", "manage", "manner", "many", "market", "marriage", "married", "mass", "massive",
    "master", "match", "mate", "matters", "maximum", "maybe", "meant", "measure", "media",
    "medical", "medium", "meet", "meeting", "member", "memory", "mention", "message", "metal",
    "method", "middle", "might", "mile", "milk", "million", "mind", "mine", "minimum", "mining",
    "minor", "minute", "mission", "mixed", "mobile", "mode", "moment", "money", "month", "moon",
    "more", "morning", "mostly", "mother", "motion", "motor", "mountain", "mouth", "move",
    "movement", "movie", "moving", "much", "multi", "multiple", "museum", "music", "must",
    "myself", "name", "national", "native", "natural", "nature", "near", "neck", "need", "network",
    "news", "next", "nice", "night", "nine", "noise", "none", "normal", "north", "northern",
    "note", "nothing", "notice", "novel", "number", "numerous", "object", "obvious", "occurred",
    "ocean", "offer", "offering", "office", "official", "often", "okay", "older", "once", "only",
    "onto", "open", "opening", "opinion", "opposed", "opposite", "option", "orange", "order",
    "origin", "others", "outside", "overall", "owned", "owner", "pack", "page", "paid", "paint",
    "painting", "pair", "panel", "paper", "parent", "park", "parties", "partner", "party", "pass",
    "passing", "past", "path", "pattern", "paying", "payment", "peak", "people", "percent",
    "perfect", "perform", "perhaps", "period", "person", "phase", "phone", "photo", "physical",
    "pick", "picture", "piece", "pilot", "pink", "place", "plan", "planned", "planning", "plastic",
    "platform", "play", "players", "playing", "pleasure", "plenty", "plot", "plus", "point",
    "pool", "popular", "port", "portion", "position", "positive", "possible", "possibly", "post",
    "pounds", "power", "powerful", "practice", "prefer", "premier", "prepare", "presence",
    "present", "pretty", "prevent", "previous", "price", "prime", "print", "prior", "private",
    "prize", "probably", "process", "produce", "product", "profile", "profit", "program",
    "progress", "project", "promise", "promote", "proof", "proper", "proposed", "protect",
    "protein", "proud", "provide", "pull", "purchase", "pure", "purpose", "push", "puts",
    "putting", "quality", "quarter", "queen", "question", "quick", "quiet", "quit", "quote",
    "radio", "raise", "random", "rare", "rate", "rather", "reach", "reading", "real", "realize",
    "reason", "receive", "recent", "record", "recovery", "reduce", "referred", "region",
    "register", "regular", "related", "release", "relevant", "relief", "remained", "remains",
    "removed", "replaced", "reported", "reports", "request", "require", "research", "reserve",
    "respect", "respond", "response", "result", "retail", "return", "revealed", "revenue",
    "review", "ride", "rights", "rise", "rising", "river", "roads", "rock", "role", "room",
    "route", "rule", "running", "runs", "rural", "safe", "said", "sale", "salt", "same", "sample",
    "save", "saving", "saying", "says", "scale", "scenes", "schedule", "scheme", "school",
    "science", "screen", "season", "seat", "second", "secret", "section", "sector", "secure",
    "seeing", "seek", "seeking", "seem", "seen", "sees", "sell", "selling", "semi", "send",
    "senior", "sense", "sent", "sentence", "separate", "series", "served", "service", "serving",
    "session", "setting", "several", "shape", "share", "sharing", "shift", "ship", "shipping",
    "shirt", "shoes", "shop", "shopping", "short", "should", "show", "showing", "shut", "signal",
    "signed", "signs", "silver", "similar", "simple", "simply", "since", "singer", "singing",
    "single", "sister", "site", "sitting", "size", "skills", "sleep", "sleeping", "slightly",
    "slow", "small", "smart", "snow", "social", "soft", "software", "solar", "sold", "solid",
    "solo", "solution", "some", "somebody", "somehow", "someone", "somewhat", "song", "soon",
    "sort", "sound", "source", "south", "southern", "space", "speaking", "special", "species",
    "specific", "speech", "speed", "spend", "spent", "split", "spoke", "spot", "spread", "spring",
    "squad", "square", "stadium", "staff", "stage", "stand", "standard", "standing", "star",
    "started", "starting", "station", "status", "stay", "staying", "steam", "steel", "step",
    "stick", "still", "stock", "stone", "stood", "storage", "store", "stories", "straight",
    "strategy", "stream", "street", "strength", "strong", "student", "studies", "studio", "study",
    "stuff", "style", "subject", "success", "such", "suddenly", "sugar", "suggest", "suit",
    "summer", "super", "supply", "support", "suppose", "surely", "surface", "surprise", "survey",
    "sweet", "switch", "system", "take", "taking", "talent", "talk", "talking", "tall", "tank",
    "task", "taste", "taught", "taxes", "teach", "teachers", "teaching", "teams", "tech", "teeth",
    "tell", "telling", "term", "test", "testing", "text", "than", "that", "theatre", "their",
    "them", "then", "theory", "therapy", "these", "they", "things", "think", "thinking", "third",
    "this", "those", "thought", "thousand", "three", "through", "throw", "thus", "ticket", "tight",
    "time", "tiny", "tips", "title", "today", "together", "told", "tomorrow", "took", "tool",
    "total", "touch", "tour", "toward", "town", "track", "trade", "trading", "traffic", "train",
    "training", "transfer", "travel", "treat", "trees", "trend", "tried", "tries", "trip", "truck",
    "true", "truly", "trust", "truth", "trying", "turned", "turning", "turns", "twenty", "twice",
    "type", "typical", "ultimate", "under", "union", "unique", "unit", "universe", "unknown",
    "unlike", "until", "updated", "upon", "upper", "urban", "useful", "user", "usual", "valley",
    "valuable", "value", "various", "vehicle", "version", "very", "victory", "views", "village",
    "visit", "voice", "volume", "wait", "waiting", "wake", "walk", "walking", "wall", "want",
    "warm", "water", "wave", "wearing", "website", "wedding", "week", "weekend", "well", "were",
    "west", "western", "what", "whatever", "when", "whenever", "whether", "which", "while",
    "whole", "whom", "whose", "wide", "wife", "wild", "will", "willing", "wind", "windows", "wing",
    "winner", "winning", "wins", "winter", "wise", "wish", "with", "without", "witness", "woman",
    "women", "wonder", "word", "work", "workers", "working", "world", "worth", "would", "writer",
    "writing", "written", "wrote", "yard", "year", "yellow", "young", "your", "yourself", "youth",
    "zero", "zone",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_count_matches_expected() {
        assert_eq!(WORDS.len(), 1357);
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
