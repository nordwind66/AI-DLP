use parking_lot::{Condvar, Mutex};
use std::time::Instant;

/// Counting semaphore with deadline-bounded waiting: limits concurrent calls into the NLP service so
/// bursts queue (bounded by the deadline) instead of piling up unbounded work behind the models.
pub struct Gate {
    permits: Mutex<usize>,
    cv: Condvar,
    waiting: Mutex<usize>,
    max_waiting: usize,
}

pub struct Permit<'a>(&'a Gate);
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *self.0.permits.lock() += 1;
        self.0.cv.notify_one();
    }
}

#[derive(Debug)]
pub enum GateError {
    QueueFull,
    Timeout,
}

impl Gate {
    pub fn new(permits: usize, max_waiting: usize) -> Gate {
        Gate { permits: Mutex::new(permits.max(1)), cv: Condvar::new(), waiting: Mutex::new(0), max_waiting }
    }
    pub fn acquire(&self, deadline: Option<Instant>) -> Result<Permit<'_>, GateError> {
        let mut p = self.permits.lock();
        if *p > 0 {
            *p -= 1;
            return Ok(Permit(self));
        }
        {
            let mut w = self.waiting.lock();
            if *w >= self.max_waiting {
                return Err(GateError::QueueFull);
            }
            *w += 1;
        }
        let res = loop {
            if *p > 0 {
                *p -= 1;
                break Ok(Permit(self));
            }
            match deadline {
                Some(d) => {
                    if self.cv.wait_until(&mut p, d).timed_out() && *p == 0 {
                        break Err(GateError::Timeout);
                    }
                }
                None => self.cv.wait(&mut p),
            }
        };
        *self.waiting.lock() -= 1;
        res
    }
}
