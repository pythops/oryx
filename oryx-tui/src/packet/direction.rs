use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum TrafficDirection {
    Ingress,
    Egress,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseDirectionError;

impl TrafficDirection {
    pub fn all() -> Vec<TrafficDirection> {
        vec![TrafficDirection::Ingress, TrafficDirection::Egress]
    }
}

impl Display for TrafficDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrafficDirection::Ingress => write!(f, "Ingress"),
            TrafficDirection::Egress => write!(f, "Egress"),
        }
    }
}

impl FromStr for TrafficDirection {
    type Err = ParseDirectionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Ingress" | "ingress" => Ok(Self::Ingress),
            "Egress" | "egress" => Ok(Self::Egress),
            _ => Err(ParseDirectionError),
        }
    }
}
