//! Patterns (LD-110): the linear-time engine of `regex` (`regex-automata`,
//! with `regex-syntax`) behind `{T-REPLACE-RX:...}` (MOD-08.22) and, later,
//! search (FEA-01.32).
//!
//! Guarantees: matching runs in time linear in the text (no backtracking
//! engine) and patterns are bounded (LD-113, LD-120): at most 1,024
//! characters; 256 KiB compiled (the engine and its lazy-DFA cache); when
//! case-insensitive, at most 200,000 code points of written ranges and
//! characters to case-fold; no Unicode category or script class (LD-123);
//! at most 100 levels of nesting (FEA-01.32); else invalid. Each pattern is parsed,
//! translated and built once, and its exact compiled size is known, so no
//! pattern from a vault can hang App. Backreferences and look-around are
//! not supported, so such a pattern is invalid; `\d`, `\w` and their
//! negations match ASCII only, as the card says. Patterns are used as
//! written, never built from field values (LD-114), so no secret reaches
//! the engine.

use core::cell::Cell;
use regex_automata::nfa::thompson::{self, pikevm};
use regex_automata::{hybrid, meta};
use regex_syntax::ast::{self, Ast, ClassSetItem, Flag, GroupKind};

/// The longest pattern, in characters (LD-113).
pub const MAX_PATTERN: usize = 1_024;
/// The compiled size and lazy-DFA cache limit, in bytes (LD-113).
pub const MAX_COMPILED: usize = 256 * 1024;
/// Code points of written ranges and characters a case-insensitive
/// pattern may make the engine case-fold (LD-120): folding costs up to
/// about 33 ns per code point, so this stays near 7 ms.
pub const MAX_FOLDED: u64 = 200_000;
/// Compiled size × text bytes one search may cost (LD-113). When the lazy DFA gives up, matching
/// costs about compiled size × text length; measured on the build Mac,
/// 3.7 × 10^9 is 250 ms, so this keeps a margin of 2.3.
pub const MAX_WORK: usize = 1_600_000_000;
/// The regex budget of one whole resolution (LD-118, LD-123): half of
/// [`MAX_WORK`], so a resolution stays within its goal on a busy Mac.
pub const RESOLUTION_BUDGET: usize = 800_000_000;
/// The least text length a search is charged for (LD-123): short texts cost
/// more per byte.
pub const MIN_CHARGED: usize = 512;
/// What the PikeVM may cost in one search run, in NFA size × text bytes
/// (FEA-01.32). Measured on the build Mac, the PikeVM costs at most about
/// 0.67 ns per unit (`(?:[a-z]{1,30}){1,30}[0-9]` on 64 KiB of letters),
/// so a run's slow path stays near 135 ms.
pub const SEARCH_BUDGET: usize = 200_000_000;

/// A compile's result.
pub enum Compiled {
    /// The regex and its compiled size in bytes (the engine's own count).
    Ok(meta::Regex, usize),
    /// It needs more than [`MAX_COMPILED`].
    TooBig,
    /// Longer than [`MAX_PATTERN`], too much to case-fold, or not a valid
    /// pattern.
    Invalid,
}

/// The largest compiled size for one search over `text_len` bytes (LD-113):
/// [`MAX_COMPILED`], and no more than [`MAX_WORK`] / `text_len`.
#[must_use]
pub fn cap_for(text_len: usize) -> usize {
    MAX_WORK
        .checked_div(text_len)
        .unwrap_or(MAX_COMPILED)
        .min(MAX_COMPILED)
}

/// Compiles a pattern; `None` when it is invalid or too big.
#[must_use]
pub fn compile(pattern: &str) -> Option<meta::Regex> {
    match compile_sized(pattern) {
        Compiled::Ok(re, _) => Some(re),
        Compiled::TooBig | Compiled::Invalid => None,
    }
}

/// Compiles a pattern for one search over `text_len` bytes: `None` also
/// when its compiled size passes [`cap_for`] (LD-113).
#[must_use]
pub fn compile_for(pattern: &str, text_len: usize) -> Option<meta::Regex> {
    match compile_sized(pattern) {
        Compiled::Ok(re, size) if size <= cap_for(text_len) => Some(re),
        Compiled::Ok(..) | Compiled::TooBig | Compiled::Invalid => None,
    }
}

/// Compiles a pattern once: the length check, one parse, the case-folding
/// bound, one translation and one build within [`MAX_COMPILED`].
#[must_use]
pub fn compile_sized(pattern: &str) -> Compiled {
    if pattern.chars().nth(MAX_PATTERN).is_some() {
        return Compiled::Invalid;
    }
    let mut fold_budget = MAX_FOLDED;
    build(pattern, MAX_NEST, &mut fold_budget)
}

/// Nesting depth of groups, classes and repetitions (FEA-01.32).
pub const MAX_NEST: u32 = 100;

/// True when `pattern` alone parses (search wraps a user's pattern in an
/// anchor group, which must not make an unbalanced pattern valid).
pub(crate) fn parses_alone(pattern: &str) -> bool {
    parser(MAX_NEST).parse(&ascii_classes(pattern)).is_ok()
}

fn parser(nest: u32) -> ast::parse::Parser {
    ast::parse::ParserBuilder::new().nest_limit(nest).build()
}

/// One parse, the case-folding bound, one translation.
fn hir(pattern: &str, nest: u32, fold_budget: &mut u64) -> Option<regex_syntax::hir::Hir> {
    let pattern = ascii_classes(pattern);
    let tree = parser(nest).parse(&pattern).ok()?;
    let width = folded_width(&tree);
    if width > *fold_budget {
        return None;
    }
    *fold_budget = fold_budget.saturating_sub(width);
    regex_syntax::hir::translate::Translator::new()
        .translate(&pattern, &tree)
        .ok()
}

fn build(pattern: &str, nest: u32, fold_budget: &mut u64) -> Compiled {
    let Some(hir) = hir(pattern, nest, fold_budget) else {
        return Compiled::Invalid;
    };
    // LD-137 (8): no full DFA and no prefilter, so vault patterns keep the
    // engine set reviewed in LD-122 whatever features other crates turn on.
    let config = meta::Config::new()
        .nfa_size_limit(Some(MAX_COMPILED))
        .onepass_size_limit(Some(MAX_COMPILED))
        .hybrid_cache_capacity(MAX_COMPILED)
        .dfa(false)
        .auto_prefilter(false);
    match meta::Builder::new().configure(config).build_from_hir(&hir) {
        Ok(re) => {
            let size = re.memory_usage().max(1);
            Compiled::Ok(re, size)
        }
        Err(e) if e.size_limit().is_some() => Compiled::TooBig,
        Err(_) => Compiled::Invalid,
    }
}

/// A search pattern (FEA-01.32): the lazy DFA first; when it gives up (a
/// pattern whose states keep growing) or must quit (a Unicode word
/// boundary next to a non-ASCII byte), the PikeVM, whose cost of about
/// compiled size × text length is paid from the run's budget. After one
/// give-up the DFA is off for that pattern, so its wasted cache fills are
/// paid once per pattern. The lazy DFA of a normal pattern never gives up, so normal
/// searches never touch the budget.
pub(crate) struct Matcher {
    dfa: Option<hybrid::dfa::DFA>,
    vm: pikevm::PikeVM,
    size: usize,
    caches: core::cell::RefCell<(Option<hybrid::dfa::Cache>, pikevm::Cache)>,
}

/// A search pattern's build result.
pub(crate) enum Built {
    Ok(Box<Matcher>),
    TooBig,
    Invalid,
}

/// The lazy DFA cache of one search pattern, and how many times it may be
/// cleared before the DFA gives up when it makes a state every few bytes.
const SEARCH_DFA_CACHE: usize = 64 * 1024;
/// The DFA checks its efficiency the first time its cache fills (no clear
/// first), so a pattern whose states keep growing wastes at most one fill
/// (LD-126 (2)).
const SEARCH_DFA_CLEARS: usize = 0;
/// At that check, the DFA gives up when it made a new state more often
/// than once per this many bytes: past that, building states costs about
/// what the PikeVM costs, so the budget should pay for it.
const SEARCH_DFA_BYTES_PER_STATE: usize = 64;
/// Meter units of one lazy DFA call besides its bytes (LD-126 (1)):
/// measured on the build Mac, a call costs about 27 ns to start.
pub const SCAN_CALL_UNITS: usize = 32;
/// Meter units per byte the lazy DFA scans: measured, up to about 2.9 ns
/// per byte on random letters.
pub const SCAN_BYTE_UNITS: usize = 3;
/// Meter units per byte of DFA states built (LD-126 (2)).
pub const CACHE_BYTE_UNITS: usize = 8;

/// Pays `units` from `meter`, or empties it and gives `None` when it holds
/// less (LD-126).
pub(crate) fn pay(meter: &Cell<usize>, units: usize) -> Option<()> {
    let left = meter.get();
    if units > left {
        meter.set(0);
        return None;
    }
    meter.set(left.saturating_sub(units));
    Some(())
}

/// Builds a search pattern App wrote around a value of at most 1,024
/// characters (no length check here), nesting up to `nest`, its case
/// folding taken from `fold_budget` (one budget per search run).
pub(crate) fn matcher(pattern: &str, nest: u32, fold_budget: &mut u64) -> Built {
    let Some(hir) = hir(pattern, nest, fold_budget) else {
        return Built::Invalid;
    };
    let nfa_config = thompson::Config::new()
        .nfa_size_limit(Some(MAX_COMPILED))
        .which_captures(thompson::WhichCaptures::None);
    let nfa = match thompson::Compiler::new()
        .configure(nfa_config)
        .build_from_hir(&hir)
    {
        Ok(nfa) => nfa,
        Err(e) if e.size_limit().is_some() => return Built::TooBig,
        Err(_) => return Built::Invalid,
    };
    let size = nfa.memory_usage().max(1);
    let dfa_config = hybrid::dfa::Config::new()
        .cache_capacity(SEARCH_DFA_CACHE)
        .minimum_cache_clear_count(Some(SEARCH_DFA_CLEARS))
        .minimum_bytes_per_state(Some(SEARCH_DFA_BYTES_PER_STATE))
        .unicode_word_boundary(true);
    let dfa = hybrid::dfa::Builder::new()
        .configure(dfa_config)
        .build_from_nfa(nfa.clone())
        .ok();
    let Ok(vm) = pikevm::PikeVM::new_from_nfa(nfa) else {
        return Built::Invalid;
    };
    let caches = (
        dfa.as_ref().map(hybrid::dfa::DFA::create_cache),
        vm.create_cache(),
    );
    Built::Ok(Box::new(Matcher {
        dfa,
        vm,
        size,
        caches: core::cell::RefCell::new(caches),
    }))
}

impl Matcher {
    /// The compiled size in bytes (the NFA's own count).
    pub(crate) fn size(&self) -> usize {
        self.size
    }

    /// Whether the pattern occurs in `text`, paid from the run's `meter`:
    /// every byte scanned, every byte of DFA states built, and the PikeVM
    /// (also from `slow`, size × max(length, 512)). `None` when the meter
    /// or `slow` cannot pay: the caller counts the text as not matching and
    /// shows the limit notice.
    pub(crate) fn is_match(
        &self,
        text: &str,
        meter: &Cell<usize>,
        slow: &mut usize,
    ) -> Option<bool> {
        pay(
            meter,
            text.len()
                .saturating_mul(SCAN_BYTE_UNITS)
                .saturating_add(SCAN_CALL_UNITS),
        )?;
        let mut caches = self.caches.try_borrow_mut().ok()?;
        let (dfa_cache, vm_cache) = &mut *caches;
        let input = regex_automata::Input::new(text).earliest(true);
        if let (Some(dfa), Some(cache)) = (&self.dfa, dfa_cache.as_mut()) {
            let (mem, clears) = (cache.memory_usage(), cache.clear_count());
            let result = dfa.try_search_fwd(cache, &input);
            // The states built in this call: whole fills for each clear,
            // plus the growth since.
            let built = cache
                .clear_count()
                .saturating_sub(clears)
                .saturating_mul(SEARCH_DFA_CACHE)
                .saturating_add(cache.memory_usage())
                .saturating_sub(mem);
            let paid = pay(meter, built.saturating_mul(CACHE_BYTE_UNITS));
            match result {
                Ok(found) => return paid.map(|()| found.is_some()),
                // Once it gives up it stays off for this pattern, so each
                // later text costs no more cache fills.
                Err(e) if matches!(e.kind(), regex_automata::MatchErrorKind::GaveUp { .. }) => {
                    *dfa_cache = None;
                }
                Err(_) => {}
            }
            paid?;
        }
        let cost = self.size.saturating_mul(text.len().max(MIN_CHARGED));
        if cost > *slow {
            return None;
        }
        pay(meter, cost.saturating_mul(2) / 3)?;
        *slow = slow.saturating_sub(cost);
        Some(self.vm.is_match(vm_cache, input))
    }
}

/// The code points a pattern makes the engine case-fold: 0 when no part of
/// it is case-insensitive, else every written range's width and every
/// written character in a class (LD-120). A negated class nested in a class
/// costs nothing more: the engine keeps it folded. A Unicode category or
/// script class (`\p{L}`, `\p{Greek}`) gives `u64::MAX`: such patterns are
/// invalid (LD-123), whatever tables another crate's features switch on in
/// the same build.
fn folded_width(tree: &Ast) -> u64 {
    struct Count {
        insensitive: bool,
        width: u64,
        unicode_class: bool,
    }
    impl ast::Visitor for Count {
        type Output = (bool, u64);
        type Err = core::convert::Infallible;
        fn finish(self) -> Result<(bool, u64), Self::Err> {
            if self.unicode_class {
                return Ok((true, u64::MAX));
            }
            Ok((self.insensitive, self.width))
        }
        fn visit_pre(&mut self, a: &Ast) -> Result<(), Self::Err> {
            let flags = match a {
                Ast::Flags(f) => Some(&f.flags),
                Ast::Group(g) => match &g.kind {
                    GroupKind::NonCapturing(f) => Some(f),
                    _ => None,
                },
                _ => None,
            };
            if flags.is_some_and(|f| f.flag_state(Flag::CaseInsensitive) == Some(true)) {
                self.insensitive = true;
            }
            if matches!(a, Ast::ClassUnicode(_)) {
                self.unicode_class = true;
            }
            Ok(())
        }
        fn visit_class_set_item_pre(&mut self, item: &ClassSetItem) -> Result<(), Self::Err> {
            let add = match item {
                ClassSetItem::Range(r) => u64::from(u32::from(r.end.c))
                    .saturating_sub(u64::from(u32::from(r.start.c)))
                    .saturating_add(1),
                ClassSetItem::Literal(_) => 1,
                ClassSetItem::Unicode(_) => {
                    self.unicode_class = true;
                    0
                }
                _ => 0,
            };
            self.width = self.width.saturating_add(add);
            Ok(())
        }
    }
    let start = Count {
        insensitive: false,
        width: 0,
        unicode_class: false,
    };
    match ast::visit(tree, start) {
        Ok((true, width)) => width,
        Ok((false, _)) | Err(_) => 0,
    }
}

/// The pattern with `\d`, `\D`, `\w` and `\W` written as ASCII classes
/// (nested classes are valid inside `[...]` too); every other escape is
/// kept as it is.
fn ascii_classes(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('d') => out.push_str("[0-9]"),
            Some('D') => out.push_str("[^0-9]"),
            Some('w') => out.push_str("[0-9A-Za-z_]"),
            Some('W') => out.push_str("[^0-9A-Za-z_]"),
            Some(n) => {
                out.push('\\');
                out.push(n);
            }
            None => out.push('\\'),
        }
    }
    out
}
