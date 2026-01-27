use std::cmp::Ordering;

use sacp_cbor::{ArrayPos, PathElem};

use crate::value::BenchValue;

pub fn canonical_key_cmp(a: &str, b: &str) -> Ordering {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    match a_bytes.len().cmp(&b_bytes.len()) {
        Ordering::Equal => a_bytes.cmp(b_bytes),
        other => other,
    }
}

pub fn sort_map_entries(entries: &mut Vec<(String, BenchValue)>) {
    entries.sort_by(|(ak, _), (bk, _)| canonical_key_cmp(ak, bk));
}

pub fn bench_value_at<'a>(value: &'a BenchValue, path: &[PathElem<'_>]) -> Option<&'a BenchValue> {
    let mut cur = value;

    for pe in path {
        match *pe {
            PathElem::Key(key) => match cur {
                BenchValue::Map(entries) => {
                    cur = bench_map_get(entries, key)?;
                }
                _ => return None,
            },
            PathElem::Index(idx) => match cur {
                BenchValue::Array(items) => {
                    cur = items.get(idx)?;
                }
                _ => return None,
            },
        }
    }

    Some(cur)
}

pub fn bench_map_get<'a>(entries: &'a [(String, BenchValue)], key: &str) -> Option<&'a BenchValue> {
    for (k, v) in entries {
        match canonical_key_cmp(k, key) {
            Ordering::Less => continue,
            Ordering::Equal => return Some(v),
            Ordering::Greater => return None,
        }
    }

    None
}

pub fn bench_map_get_many<'a>(
    entries: &'a [(String, BenchValue)],
    keys: &[&str],
    out: &mut [Option<&'a BenchValue>],
) -> Result<(), String> {
    if keys.len() != out.len() {
        return Err("output length mismatch".to_string());
    }

    for slot in out.iter_mut() {
        *slot = None;
    }

    if keys.is_empty() || entries.is_empty() {
        return Ok(());
    }

    let mut idxs: Vec<usize> = (0..keys.len()).collect();
    idxs.sort_by(|&i, &j| canonical_key_cmp(keys[i], keys[j]));

    for w in idxs.windows(2) {
        if keys[w[0]] == keys[w[1]] {
            return Err("duplicate query key".to_string());
        }
    }

    let mut entry_idx = 0usize;
    for &key_idx in &idxs {
        let key = keys[key_idx];

        while entry_idx < entries.len() {
            match canonical_key_cmp(entries[entry_idx].0.as_str(), key) {
                Ordering::Less => entry_idx += 1,
                Ordering::Equal => {
                    out[key_idx] = Some(&entries[entry_idx].1);
                    entry_idx += 1;
                    break;
                }
                Ordering::Greater => break,
            }
        }
    }

    Ok(())
}

pub fn bench_value_set(
    root: &mut BenchValue,
    path: &[PathElem<'_>],
    value: BenchValue,
) -> Result<(), String> {
    let (container, last) = parent_container(root, path)?;
    match (container, last) {
        (ContainerMut::Map(entries), PathElem::Key(key)) => {
            if let Some(idx) = map_find_index(entries, key) {
                entries[idx].1 = value;
                return Ok(());
            }
            insert_sorted(entries, key.to_string(), value)
        }
        (ContainerMut::Array(items), PathElem::Index(index)) => {
            if *index >= items.len() {
                return Err("array index out of bounds".to_string());
            }
            items[*index] = value;
            Ok(())
        }
        _ => Err("path does not match container".to_string()),
    }
}

pub fn bench_value_insert(
    root: &mut BenchValue,
    path: &[PathElem<'_>],
    value: BenchValue,
) -> Result<(), String> {
    let (container, last) = parent_container(root, path)?;
    match (container, last) {
        (ContainerMut::Map(entries), PathElem::Key(key)) => {
            if map_find_index(entries, key).is_some() {
                return Err("map key already exists".to_string());
            }
            insert_sorted(entries, key.to_string(), value)
        }
        (ContainerMut::Array(items), PathElem::Index(index)) => {
            if *index > items.len() {
                return Err("array index out of bounds".to_string());
            }
            items.insert(*index, value);
            Ok(())
        }
        _ => Err("path does not match container".to_string()),
    }
}

pub fn bench_value_replace(
    root: &mut BenchValue,
    path: &[PathElem<'_>],
    value: BenchValue,
) -> Result<(), String> {
    let (container, last) = parent_container(root, path)?;
    match (container, last) {
        (ContainerMut::Map(entries), PathElem::Key(key)) => {
            let idx = map_find_index(entries, key).ok_or_else(|| "map key missing".to_string())?;
            entries[idx].1 = value;
            Ok(())
        }
        (ContainerMut::Array(items), PathElem::Index(index)) => {
            if *index >= items.len() {
                return Err("array index out of bounds".to_string());
            }
            items[*index] = value;
            Ok(())
        }
        _ => Err("path does not match container".to_string()),
    }
}

pub fn bench_value_delete(root: &mut BenchValue, path: &[PathElem<'_>]) -> Result<(), String> {
    let (container, last) = parent_container(root, path)?;
    match (container, last) {
        (ContainerMut::Map(entries), PathElem::Key(key)) => {
            let idx = map_find_index(entries, key).ok_or_else(|| "map key missing".to_string())?;
            entries.remove(idx);
            Ok(())
        }
        (ContainerMut::Array(items), PathElem::Index(index)) => {
            if *index >= items.len() {
                return Err("array index out of bounds".to_string());
            }
            items.remove(*index);
            Ok(())
        }
        _ => Err("path does not match container".to_string()),
    }
}

pub fn bench_value_splice(
    root: &mut BenchValue,
    array_path: &[PathElem<'_>],
    pos: ArrayPos,
    delete: usize,
    inserts: Vec<BenchValue>,
) -> Result<(), String> {
    let target = value_at_mut(root, array_path)?;
    let BenchValue::Array(items) = target else {
        return Err("splice target is not an array".to_string());
    };

    let len = items.len();
    let index = match pos {
        ArrayPos::At(i) => i,
        ArrayPos::End => len,
    };

    if matches!(pos, ArrayPos::End) && delete != 0 {
        return Err("splice at end cannot delete".to_string());
    }

    if index > len || delete > len.saturating_sub(index) {
        return Err("splice out of bounds".to_string());
    }

    let end = index + delete;
    items.splice(index..end, inserts);
    Ok(())
}

enum ContainerMut<'a> {
    Map(&'a mut Vec<(String, BenchValue)>),
    Array(&'a mut Vec<BenchValue>),
}

fn parent_container<'a, 'p>(
    root: &'a mut BenchValue,
    path: &'p [PathElem<'p>],
) -> Result<(ContainerMut<'a>, &'p PathElem<'p>), String> {
    let (last, parent_path) = path
        .split_last()
        .ok_or_else(|| "empty path".to_string())?;
    let parent = value_at_mut(root, parent_path)?;

    match parent {
        BenchValue::Map(entries) => Ok((ContainerMut::Map(entries), last)),
        BenchValue::Array(items) => Ok((ContainerMut::Array(items), last)),
        _ => Err("path does not resolve to container".to_string()),
    }
}

fn value_at_mut<'a>(
    root: &'a mut BenchValue,
    path: &[PathElem<'_>],
) -> Result<&'a mut BenchValue, String> {
    if path.is_empty() {
        return Ok(root);
    }

    match path[0] {
        PathElem::Key(key) => match root {
            BenchValue::Map(entries) => {
                let idx = map_find_index(entries, key).ok_or_else(|| "map key missing".to_string())?;
                value_at_mut(&mut entries[idx].1, &path[1..])
            }
            _ => Err("expected map".to_string()),
        },
        PathElem::Index(idx) => match root {
            BenchValue::Array(items) => {
                let item = items
                    .get_mut(idx)
                    .ok_or_else(|| "array index out of bounds".to_string())?;
                value_at_mut(item, &path[1..])
            }
            _ => Err("expected array".to_string()),
        },
    }
}

fn map_find_index(entries: &[(String, BenchValue)], key: &str) -> Option<usize> {
    for (idx, (k, _)) in entries.iter().enumerate() {
        match canonical_key_cmp(k, key) {
            Ordering::Less => continue,
            Ordering::Equal => return Some(idx),
            Ordering::Greater => return None,
        }
    }

    None
}

fn insert_sorted(
    entries: &mut Vec<(String, BenchValue)>,
    key: String,
    value: BenchValue,
) -> Result<(), String> {
    let mut idx = 0usize;
    while idx < entries.len() {
        match canonical_key_cmp(entries[idx].0.as_str(), key.as_str()) {
            Ordering::Less => idx += 1,
            Ordering::Equal => return Err("duplicate map key".to_string()),
            Ordering::Greater => break,
        }
    }

    entries.insert(idx, (key, value));
    Ok(())
}
