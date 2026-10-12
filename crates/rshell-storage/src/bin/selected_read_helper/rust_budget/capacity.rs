use super::Reject;
use std::alloc::Layout;

pub fn add(a: usize, b: usize) -> Result<usize, Reject> {
    a.checked_add(b).ok_or(Reject::Overflow)
}

pub fn array<T>(n: usize) -> Result<Layout, Reject> {
    Layout::array::<T>(n).map_err(|_| Reject::Overflow)
}

/// 对 helper artifact 的 element Layout 计算，不使用父编译器的私有类型布局。
pub fn array_for(element: Layout, n: usize) -> Result<Layout, Reject> {
    let size = element.size().checked_mul(n).ok_or(Reject::Overflow)?;
    Layout::from_size_align(size, element.align()).map_err(|_| Reject::Overflow)
}

/// 锁定 RawVec::grow_amortized 的容量上界，含搬迁期间旧、新 backing。
/// initial 是真实 with_capacity 参数，n 是全部 append 后的最大长度。
pub fn vec_peak<T>(initial: usize, n: usize) -> Result<usize, Reject> {
    vec_peak_for(Layout::new::<T>(), initial, n)
}

pub fn vec_peak_for(element: Layout, initial: usize, n: usize) -> Result<usize, Reject> {
    if element.size() == 0 {
        return Ok(0);
    }
    if n <= initial {
        return Ok(array_for(element, initial)?.size());
    }
    let minimum = if element.size() == 1 {
        8
    } else if element.size() <= 1024 {
        4
    } else {
        1
    };
    let old = n - 1;
    let next = old
        .checked_mul(2)
        .ok_or(Reject::Overflow)?
        .max(n)
        .max(minimum);
    Ok(array_for(element, initial)?.size().max(add(
        array_for(element, old)?.size(),
        array_for(element, next)?.size(),
    )?))
}

/// repr(Rust) struct 字段的排列无关上界；仅供已列全字段的源模型使用。
pub fn struct_upper(fields: &[Layout]) -> Result<Layout, Reject> {
    let align = fields.iter().map(Layout::align).max().unwrap_or(1);
    let mut size = 0usize;
    for field in fields {
        let rounded = add(field.size(), align - 1)? & !(align - 1);
        size = add(size, rounded)?;
    }
    Layout::from_size_align(size, align).map_err(|_| Reject::Overflow)
}
