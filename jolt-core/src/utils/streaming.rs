// An iterator that maps over the values of `iter` with `f`, which modifies its accumulated state.
pub struct MapState<S, I, F> {
    state: S,
    iter: std::iter::Cycle<I>,
    f: F,
}

pub fn map_state<B, S, I, F>(initial_state: S, iter: I, f: F) -> MapState<S, I, F>
where
    I: Iterator + Clone,
    F: FnMut(&mut S, I::Item) -> B,
{
    MapState::new(initial_state, iter, f)
}

impl<S, I, F> MapState<S, I, F> {
    fn new<B>(initial_state: S, iter: I, f: F) -> Self
    where
        I: Iterator + Clone,
        F: FnMut(&mut S, I::Item) -> B,
    {
        MapState {
            state: initial_state,
            iter: iter.cycle(),
            f,
        }
    }
}

impl<B, S, I, F> Iterator for MapState<S, I, F>
where
    I: Iterator + Clone,
    F: FnMut(&mut S, I::Item) -> B,
{
    type Item = B;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|x| (self.f)(&mut self.state, x))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}
