use certs_types::expiry::Expiry;
use iocraft::{
    AnyElement, Color, FlexDirection, Props, component, element,
    prelude::{Text, View},
};
use jiff::{Span, SpanRound, Timestamp, Unit, tz::TimeZone};

#[derive(Default, Props)]
pub(crate) struct ExpiryViewProps<'a> {
    pub(crate) expiry: Option<&'a Expiry>,
}

#[component]
pub(crate) fn ExpiryView<'a>(props: &ExpiryViewProps<'a>) -> impl Into<AnyElement<'static>> {
    let Some(&Expiry {
        not_before,
        not_after,
    }) = props.expiry
    else {
        return element! { View { Text(content: "no expiry", color: Color::Red) } };
    };

    let now = Timestamp::now();

    element! {
        View(flex_direction: FlexDirection::Column) {
            NotBefore(now, not_before)
            NotAfter(now, not_after)
        }
    }
}

#[derive(Default, Props)]
pub(crate) struct NotBeforeProps {
    pub(crate) now: Timestamp,
    pub(crate) not_before: Timestamp,
}

#[component]
fn NotBefore(props: &NotBeforeProps) -> impl Into<AnyElement<'static>> {
    let (when, human_relative) = match determine_relative_time(props.not_before, props.now) {
        Ok((when, human_relative)) => (when, human_relative),
        Err(err) => (When::Never, err),
    };

    let color = match when {
        When::Future => Color::Yellow,
        When::Past => Color::Green,
        When::Never => Color::Grey,
    };

    element! {
        View(gap: 1, flex_direction: FlexDirection::Row) {
            Text(content: "not before:", color: Color::Green)
            Text(content: props.not_before.to_string(), color)
            Text(content: human_relative, color)
        }
    }
}

#[derive(Default, Props)]
pub(crate) struct NotAfterProps {
    pub(crate) now: Timestamp,
    pub(crate) not_after: Timestamp,
}

#[component]
fn NotAfter(props: &NotAfterProps) -> impl Into<AnyElement<'static>> {
    let (when, human_relative) = match determine_relative_time(props.not_after, props.now) {
        Ok((when, human_relative)) => (when, human_relative),
        Err(err) => (When::Never, err),
    };

    let color = match when {
        When::Future => Color::Yellow,
        When::Past => Color::Green,
        When::Never => Color::Grey,
    };

    element! {
        View(gap: 1, flex_direction: FlexDirection::Row) {
            Text(content: "not after: ", color: Color::Green)
            Text(content: props.not_after.to_string(), color)
            Text(content: human_relative, color)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum When {
    Future,
    Past,
    Never,
}

/// Formats a timestamp as a relative time string.
///
/// If the time is within 1 hour from now, minutes are used.
/// If the time is within 1 day from now, hours and minutes are used.
/// If the time is within 1 week from now, days and hours are used.
/// If the time is within 1 month from now, weeks and days are used.
/// If the time is within 1 year from now, months and days are used.
/// If the time is more than 1 year from now, years and months are used.
///
/// If the time is in the past, the time is formatted as `ago` with the number of units.
/// If the time is in the future, the time is formatted as `in` with the number of units.
///
/// Examples:
/// - `in 3m`
/// - `3m ago`
/// - `in 1h`
/// - `1h ago`
/// - `in 3w 4d`
/// - `in 1y 2mo`
/// - `1y 2mo ago`
/// - `in 10y`
/// - `10y ago`
fn determine_relative_time(
    time: Timestamp,
    relative_to: Timestamp,
) -> Result<(When, String), String> {
    let (when, span) = round_relative_human(time, relative_to)?;

    match when {
        When::Future => Ok((when, format!("(in {:#})", span))),
        When::Past => Ok((when, format!("({:#} ago)", span))),
        When::Never => Err("unable to calculate span".to_string()),
    }
}

fn round_relative_human(time: Timestamp, relative_to: Timestamp) -> Result<(When, Span), String> {
    let diff = relative_to.duration_until(time);
    let in_the_future = diff.is_positive();

    let Ok(span) = relative_to.until(time) else {
        return Err("unable to calculate span".to_string());
    };

    let relative_date = relative_to.to_zoned(TimeZone::UTC);
    let round_config = if span
        .total((Unit::Year, relative_date.date()))
        .unwrap()
        .abs()
        > 1.0
    {
        SpanRound::new()
            .largest(jiff::Unit::Year)
            .smallest(jiff::Unit::Month)
            .relative(&relative_date)
    // if it's in months from now:
    } else if span
        .total((Unit::Month, relative_date.date()))
        .unwrap()
        .abs()
        > 1.0
    {
        SpanRound::new()
            .largest(jiff::Unit::Month)
            .smallest(jiff::Unit::Day)
            .relative(&relative_date)
    // if it's in weeks from now:
    } else if span
        .total((Unit::Week, relative_date.date()))
        .unwrap()
        .abs()
        > 1.0
    {
        SpanRound::new()
            .largest(jiff::Unit::Week)
            .smallest(jiff::Unit::Day)
            .relative(&relative_date)
    // if it's in days from now:
    } else if span.total((Unit::Day, relative_date.date())).unwrap().abs() > 1.0 {
        SpanRound::new()
            .largest(jiff::Unit::Day)
            .smallest(jiff::Unit::Hour)
            .relative(&relative_date)
    // if it's in hours from now:
    } else if span
        .total((Unit::Hour, relative_date.date()))
        .unwrap()
        .abs()
        > 1.0
    {
        SpanRound::new()
            .largest(jiff::Unit::Hour)
            .smallest(jiff::Unit::Minute)
            .relative(&relative_date)
    // it's in minutes from now:
    } else {
        SpanRound::new()
            .largest(jiff::Unit::Minute)
            .smallest(jiff::Unit::Second)
            .relative(&relative_date)
    };

    let span = span.round(round_config).expect("unable to round span");
    let when = if in_the_future {
        When::Future
    } else {
        When::Past
    };

    Ok((when, span))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determine_relative_time_same_time() {
        let now = Timestamp::from_second(1721635200).unwrap();
        let not_before = Timestamp::from_second(1721635200).unwrap();

        let (when, human_relative) = determine_relative_time(not_before, now).unwrap();
        assert_eq!(when, When::Past);
        assert_eq!(human_relative, "(0s ago)");
    }

    #[test]
    fn determine_relative_time_future() {
        let now = Timestamp::from_second(1721635200).unwrap();
        let not_before = Timestamp::from_second(1721635300).unwrap();

        let (when, human_relative) = determine_relative_time(not_before, now).unwrap();
        assert_eq!(when, When::Future);
        assert_eq!(human_relative, "(in 1m 40s)");
    }

    #[test]
    fn determine_relative_time_future_in_minutes() {
        let now = Timestamp::from_second(1721635200).unwrap();
        let not_before = Timestamp::from_second(1721635260).unwrap();

        let (when, human_relative) = determine_relative_time(not_before, now).unwrap();
        assert_eq!(when, When::Future);
        assert_eq!(human_relative, "(in 1m)");
    }

    #[test]
    fn determine_relative_time_future_in_hours() {
        let now = Timestamp::from_second(1721635200).unwrap();
        let not_before = Timestamp::from_second(1721638860).unwrap();

        let (when, human_relative) = determine_relative_time(not_before, now).unwrap();
        assert_eq!(when, When::Future);
        assert_eq!(human_relative, "(in 1h 1m)");
    }

    #[test]
    fn determine_relative_time_future_in_days() {
        let now = Timestamp::from_second(1721635200).unwrap();
        let not_before = now + jiff::SignedDuration::from_hours(25);

        let (when, human_relative) = determine_relative_time(not_before, now).unwrap();
        assert_eq!(when, When::Future);
        assert_eq!(human_relative, "(in 1d 1h)");
    }
}
