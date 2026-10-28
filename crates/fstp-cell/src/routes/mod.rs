//! The route table (design section 5.4). `Route::new` takes a risk class
//! with no default, so a route without one does not compile (I-78).

/// The risk class of a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiskClass {
    /// A read or a low-risk command.
    Normal,
    /// A high-risk action that needs a step-up.
    HighRisk(fstp_cell_core::gate::HighRiskAction),
}

/// One route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    method: &'static str,
    path: &'static str,
    risk: RiskClass,
}

impl Route {
    /// A route with its risk class.
    pub const fn new(method: &'static str, path: &'static str, risk: RiskClass) -> Route {
        Route { method, path, risk }
    }

    /// The method, path and risk class.
    pub fn parts(&self) -> (&'static str, &'static str, RiskClass) {
        (self.method, self.path, self.risk)
    }
}
