# HedgeDoc note API source facts (v1.11.0)

## Endpoint
- GET /:noteId showNote via findNote
- Local modeling route: /local/hedgedoc/notes/{id}

## checkViewPermission (util.js / realtime.js)
- private: authenticated AND ownerId === user.id
- limited | protected: authenticated
- freely | editable | locked: public view

## mayEdit (realtime.js)
- freely: anyone
- editable | limited: logged-in users
- locked | private | protected: owner only

## findNote
- Always runs checkViewPermission; fail -> errorForbidden

## Security contact
- SECURITY.md: SISheogorath OpenPGP private report