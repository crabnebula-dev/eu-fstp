// The English labels of the tenant admin's funder profiles page (Daniel,
// 2026-11-15 late). Every id starts with `admin.profiles.`. Plain language
// only (docs/design/10). No approved or legal text is held here.

export const ADMIN_PROFILE_LABELS: Readonly<Record<string, string>> = {
  "admin.profiles.title": "Funder profiles",
  "admin.profiles.intro":
    "A funder profile sets the funder reports and the funder visibility elements of a programme. The platform ships versioned profiles. You may copy one into a profile your organisation owns and edit it. Each save makes a new version, and a programme pins one version through P-53.",
  "admin.profiles.back": "Back to your work",
  "admin.profiles.list.heading": "Profiles",
  "admin.profiles.list.caption": "Shipped and tenant profiles, by version",
  "admin.profiles.col.id": "Profile",
  "admin.profiles.col.version": "Version",
  "admin.profiles.col.owner": "Owner",
  "admin.profiles.col.source": "Copied from",
  "admin.profiles.owner.shipped": "Shipped by the platform",
  "admin.profiles.owner.tenant": "Your organisation",
  "admin.profiles.source.none": "Not a copy",
  "admin.profiles.source.row": "{profile} version {version}",
  "admin.profiles.copy.heading": "Copy a profile",
  "admin.profiles.copy.from": "Profile to copy",
  "admin.profiles.copy.id": "New profile id, starting with tenant-",
  "admin.profiles.copy.submit": "Copy the profile",
  "admin.profiles.copy.invalid": "Write an id that starts with tenant- and holds lower-case letters, digits and hyphens.",
  "admin.profiles.copy.done": "Profile {id} version 1 is saved.",
  "admin.profiles.edit.heading": "Edit a profile of your organisation",
  "admin.profiles.edit.none": "Your organisation owns no profile yet. Copy one first.",
  "admin.profiles.edit.which": "Profile to edit",
  "admin.profiles.edit.text": "Profile text (JSON)",
  "admin.profiles.edit.submit": "Save a new version",
  "admin.profiles.edit.invalid": "The profile text is not one JSON object.",
  "admin.profiles.edit.done": "A new version of profile {id} is saved.",
};
