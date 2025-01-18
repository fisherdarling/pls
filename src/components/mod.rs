use jiff::{Span, SpanRound, Unit, Zoned};

pub mod connection;
pub mod x509;

pub(crate) fn round_relative_human(span: Span, relative_to: Zoned) -> Span {
    let round_config = if span.total((Unit::Year, relative_to.date())).unwrap().abs() > 1.0 {
        SpanRound::new()
            .largest(jiff::Unit::Year)
            .smallest(jiff::Unit::Month)
            .relative(&relative_to)
    // if it's in months from now:
    } else if span.total((Unit::Month, relative_to.date())).unwrap().abs() > 1.0 {
        SpanRound::new()
            .largest(jiff::Unit::Month)
            .smallest(jiff::Unit::Day)
            .relative(&relative_to)
    // it's in days from now:
    } else {
        SpanRound::new()
            .largest(jiff::Unit::Day)
            .smallest(jiff::Unit::Minute)
            .relative(&relative_to)
    };

    span.round(round_config).expect("unable to round span")
}
