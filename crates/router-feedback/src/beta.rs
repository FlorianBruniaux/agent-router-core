//! Regularized incomplete beta and its quantiles, for the Jeffreys interval of
//! the accepted rate. Bounded work: a fixed number of continued-fraction
//! iterations and of bisection steps. No dependency.

const MAX_ITERATIONS: usize = 300;
const EPSILON: f64 = 1e-15;
const TINY: f64 = 1e-300;
const BISECTION_STEPS: usize = 100;

/// Lanczos approximation (g = 7, n = 9), valid for `x >= 0.5`.
fn ln_gamma(x: f64) -> f64 {
    const C: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    let x = x - 1.0;
    let sum = C[0]
        + C[1..]
            .iter()
            .enumerate()
            .map(|(i, c)| c / (x + (i + 1) as f64))
            .sum::<f64>();
    let t = x + 7.5;
    0.5 * (2.0 * std::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + sum.ln()
}

/// Modified Lentz evaluation of the continued fraction of `I_x(a, b)`.
fn continued_fraction(a: f64, b: f64, x: f64) -> f64 {
    let (qab, qap, qam) = (a + b, a + 1.0, a - 1.0);
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < TINY {
        d = TINY;
    }
    d = 1.0 / d;
    let mut h = d;
    for m in 1..=MAX_ITERATIONS {
        let m = m as f64;
        let m2 = 2.0 * m;
        let even = m * (b - m) * x / ((qam + m2) * (a + m2));
        d = 1.0 + even * d;
        if d.abs() < TINY {
            d = TINY;
        }
        c = 1.0 + even / c;
        if c.abs() < TINY {
            c = TINY;
        }
        d = 1.0 / d;
        h *= d * c;
        let odd = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2));
        d = 1.0 + odd * d;
        if d.abs() < TINY {
            d = TINY;
        }
        c = 1.0 + odd / c;
        if c.abs() < TINY {
            c = TINY;
        }
        d = 1.0 / d;
        let delta = d * c;
        h *= delta;
        if (delta - 1.0).abs() < EPSILON {
            break;
        }
    }
    h
}

/// `I_x(a, b)` for `a, b >= 0.5` and `x` in `[0, 1]`.
pub(crate) fn regularized_beta(a: f64, b: f64, x: f64) -> f64 {
    debug_assert!(a >= 0.5 && b >= 0.5);
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let ln_front = ln_gamma(a + b) - ln_gamma(a) - ln_gamma(b) + a * x.ln() + b * (1.0 - x).ln();
    let front = ln_front.exp();
    if x < (a + 1.0) / (a + b + 2.0) {
        front * continued_fraction(a, b, x) / a
    } else {
        1.0 - front * continued_fraction(b, a, 1.0 - x) / b
    }
}

/// Quantile of Beta(a, b) by bisection on the monotone CDF.
pub(crate) fn beta_quantile(a: f64, b: f64, p: f64) -> f64 {
    let (mut low, mut high) = (0.0, 1.0);
    for _ in 0..BISECTION_STEPS {
        let mid = (low + high) / 2.0;
        if regularized_beta(a, b, mid) < p {
            low = mid;
        } else {
            high = mid;
        }
    }
    (low + high) / 2.0
}

fn micros(value: f64) -> u64 {
    (value * 1e6).round().clamp(0.0, 1e6) as u64
}

/// Equal-tailed 95% Jeffreys interval, Beta(x + 1/2, n - x + 1/2), in micros.
/// Follows Brown, Cai and DasGupta: the lower bound is 0 when `accepted` is 0
/// and the upper bound is 1 when `rejected` is 0.
pub(crate) fn jeffreys_interval_micros(accepted: u64, rejected: u64) -> (u64, u64) {
    let a = accepted as f64 + 0.5;
    let b = rejected as f64 + 0.5;
    let lower = if accepted == 0 {
        0
    } else {
        micros(beta_quantile(a, b, 0.025))
    };
    let upper = if rejected == 0 {
        1_000_000
    } else {
        micros(beta_quantile(a, b, 0.975))
    };
    (lower, upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference values come from an independent computation: Simpson
    /// integration of the Beta density in the substitution t = sin^2(theta)
    /// (400000 points, plain Python `math.lgamma`), then bisection. They agree
    /// with the published Jeffreys interval 0.2235 to 0.7765 for 5 of 10.
    fn near(value: f64, expected: f64) {
        assert!(
            (value - expected).abs() < 2e-7,
            "{value} differs from {expected}"
        );
    }

    #[test]
    fn jeffreys_quantiles_match_the_independent_reference() {
        near(beta_quantile(0.5, 10.5, 0.975), 0.217_196_267_509);
        near(beta_quantile(5.5, 5.5, 0.025), 0.223_528_670_253);
        near(beta_quantile(5.5, 5.5, 0.975), 0.776_471_329_747);
        near(beta_quantile(10.5, 0.5, 0.025), 0.782_803_732_491);
        near(beta_quantile(3.5, 7.5, 0.025), 0.092_694_593_935);
        near(beta_quantile(3.5, 7.5, 0.975), 0.605_818_318_149);
        near(beta_quantile(20.5, 5.5, 0.025), 0.615_798_209_657);
        near(beta_quantile(20.5, 5.5, 0.975), 0.919_321_312_575);
    }

    #[test]
    fn arcsine_case_has_a_closed_form() {
        // Beta(1/2, 1/2) has CDF (2/pi) asin(sqrt(x)), so q = sin^2(pi p / 2).
        for p in [0.025, 0.5, 0.975] {
            let exact = (std::f64::consts::PI * p / 2.0).sin().powi(2);
            near(beta_quantile(0.5, 0.5, p), exact);
        }
    }

    #[test]
    fn interval_in_micros_and_boundary_conventions() {
        assert_eq!(jeffreys_interval_micros(5, 5), (223_529, 776_471));
        assert_eq!(jeffreys_interval_micros(0, 10), (0, 217_196));
        assert_eq!(jeffreys_interval_micros(10, 0), (782_804, 1_000_000));
        assert_eq!(jeffreys_interval_micros(0, 0), (0, 1_000_000));
    }
}
