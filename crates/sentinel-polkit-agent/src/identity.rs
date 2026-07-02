// SPDX-FileCopyrightText: 2025 Atay Özcan <atay@oezcan.me>
// SPDX-License-Identifier: GPL-3.0-or-later
//! Pick which `unix-user` identity to authenticate as from polkit's list of
//! eligible identities.

use std::collections::HashMap;
use zvariant::OwnedValue;

pub type Identity = (String, HashMap<String, OwnedValue>);

/// Pick the identity to authenticate as: the `unix-user` whose uid is the
/// agent's own (the logged-in user). Returns `None` if the running user is
/// not among polkit's offered identities.
///
/// # Why not fall back to the first offered identity
///
/// Sentinel replaces polkit's password prompt with a confirmation dialog,
/// so authenticating "as" an identity means: one Allow click grants it.
/// Authenticating as an identity the user *doesn't own* would therefore let
/// a single click satisfy an `auth_admin` action as root/another admin with
/// no credential — defeating the very gate polkit is asking about.
///
/// This is not a limitation in practice: `install.sh` installs a polkit
/// admin rule making the logged-in user an administrator, so polkit always
/// offers that user's own uid for the actions they can perform, and the
/// match below succeeds. When the running user is genuinely *not* an
/// eligible identity, declining (→ the agent errors → polkit falls back to
/// a password) is the correct, fail-closed outcome — the same fallback the
/// installer documents for a system without the admin rule.
pub fn pick(identities: &[Identity], own_uid: u32) -> Option<u32> {
    for (kind, details) in identities {
        if kind != "unix-user" {
            continue;
        }
        let Some(uid_val) = details.get("uid") else {
            continue;
        };
        let Ok(uid): Result<u32, _> = uid_val.try_into() else {
            continue;
        };
        if uid == own_uid {
            return Some(uid);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use zvariant::Value;

    fn unix_user(uid: u32) -> Identity {
        let mut details: HashMap<String, OwnedValue> = HashMap::new();
        details.insert("uid".to_string(), Value::U32(uid).try_to_owned().unwrap());
        ("unix-user".to_string(), details)
    }

    fn unix_group(gid: u32) -> Identity {
        let mut details: HashMap<String, OwnedValue> = HashMap::new();
        details.insert("gid".to_string(), Value::U32(gid).try_to_owned().unwrap());
        ("unix-group".to_string(), details)
    }

    #[test]
    fn prefers_matching_uid_even_when_listed_later() {
        let ids = vec![unix_user(0), unix_user(1000), unix_user(1001)];
        assert_eq!(pick(&ids, 1000), Some(1000));
    }

    #[test]
    fn fails_closed_when_own_uid_absent() {
        // The running user isn't among the offered identities (e.g. an
        // auth_admin action on a system where this user isn't an admin).
        // We must NOT authenticate as someone else — decline instead, so a
        // single Allow click can't stand in for an admin credential.
        let ids = vec![unix_user(0), unix_user(1001)];
        assert_eq!(pick(&ids, 9999), None);
    }

    #[test]
    fn skips_non_unix_user_kinds() {
        let ids = vec![unix_group(0), unix_user(1000)];
        assert_eq!(pick(&ids, 1000), Some(1000));
    }

    #[test]
    fn returns_none_for_empty_identities() {
        assert_eq!(pick(&[], 1000), None);
    }

    #[test]
    fn returns_none_when_only_non_unix_user() {
        let ids = vec![unix_group(100), unix_group(101)];
        assert_eq!(pick(&ids, 1000), None);
    }

    #[test]
    fn skips_entries_missing_uid_field() {
        let no_uid: Identity = ("unix-user".to_string(), HashMap::new());
        let ids = vec![no_uid, unix_user(1000)];
        assert_eq!(pick(&ids, 1000), Some(1000));
    }
}
