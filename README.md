# Java Object Modify — Burp Suite Extension

![Java](https://img.shields.io/badge/Java-17+-blue) ![Burp Montoya API](https://img.shields.io/badge/Burp-Montoya%20API-orange)

A Burp Suite extension that adds a **"Java Object Modify"** editor tab to Repeater,
Proxy intercept, and any message editor that supports extension-provided editors.
It decodes Java-serialized objects (`AC ED` streams) found anywhere in an HTTP
message — **body, header, or base64-encoded cookie** — shows them as a navigable
tree, lets you edit scalar values, and re-serializes the modified stream back into
the live message.

No external dependencies: the serialization parser/encoder is implemented from
scratch in Java.

---

## Table of Contents

- [Features](#features)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Compile from source](#compile-from-source)
- [Install in Burp](#install-in-burp)
- [Usage](#usage)
- [Themes](#themes)
- [Project layout](#project-layout)
- [Known limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

- **Native Java serialization engine** — no ysoserial, no external jars.
  - `TC_OBJECT`, `TC_STRING` / `TC_LONGSTRING`, `TC_ARRAY`, `TC_CLASSDESC`,
    `TC_PROXYCLASSDESC`, `TC_ENUM`, `TC_CLASS`, `TC_REFERENCE`, `TC_NULL`,
    `TC_RESET`, `TC_BLOCKDATA` / `TC_BLOCKDATALONG`, `TC_ENDBLOCKDATA`
  - Inheritance chains (superclass descriptors)
  - Self-references and object arrays (cross-element references)
  - Custom `writeObject()` block data (replayed verbatim)
- **Finds streams anywhere in the message**:
  - Raw `AC ED` bytes in body or headers
  - **Base64-encoded streams** (e.g. a Java-serialized cookie), auto-detected,
    decoded on parse and re-encoded on apply
- **Editable scalar values** — `String`, `int`, `long`, `short`, `byte`,
  `float`, `double`, `boolean`, `char`
- **Tree view** of the object graph with type-colored nodes and icons
  (objects, strings, numbers, booleans, null, references)
- **Auto-apply or manual apply** — live message updates per keystroke, or a
  dedicated **Apply edits** button
- **Multi-object streams** — pick the top-level object index to inspect
- **Light / Dark / System themes**, persisted across sessions via Burp preferences
- Byte-identical round-trip for most streams; semantically-correct
  re-serialization for complex sharing graphs

---

## How it works

1. When a message opens, the extension scans the whole raw request/response for
   a serialized stream:
   - raw `AC ED` magic bytes, **or**
   - a base64 token that decodes to an `AC ED` stream (common for cookies)
2. The stream is parsed into a node tree with per-instance field values.
3. The tree is rendered in the tab; selecting a scalar value shows an edit card.
4. On edit, the tree is re-serialized, then:
   - raw streams are **spliced** back at the exact byte offset,
   - base64 streams are **re-encoded** and spliced over the original token,
     replacing it completely (including its `=` padding).

The edited message is returned to Burp through the extension-provided editor API,
so Repeater sends it on your next request.

---

## Requirements

| Requirement | Version |
|---|---|
| Burp Suite | 2023.9+ (Montoya API era) |
| Java | 17+ (JDK for compiling, JRE is fine for running) |
| Montoya API jar | any version ≥ your Burp's API; default build uses `2026.7` |

> Older Burp versions using the legacy `IBurpExtender` API are **not** supported
> by this codebase.

---

## Compile from source

### Option A — build script

```bash
git clone <your-repo-url>
cd <repo-dir>

# download the Montoya API jar (or point build.sh at your own copy)
curl -L -o /tmp/montoya-api.jar \
  https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2026.7/montoya-api-2026.7.jar

sh build.sh /tmp/montoya-api.jar
# -> dist/java-object-modify-0.1.0.jar
```

### Option B — manual `javac` / `jar`

```bash
mkdir -p build/classes
javac -cp /tmp/montoya-api.jar -d build/classes \
  src/javaser/JavaSerializationProtocol.java \
  src/burp/javaobjectmodify/JavaObjectModifyExtension.java

# bundle the service descriptor next to the classes
cp -r src/burp/META-INF build/

# package
(cd build/classes && jar --create --file ../../dist/java-object-modify-0.1.0.jar . ../META-INF)
```

### Matching your Burp version

Montoya API releases live on Maven Central:

```
https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/<VERSION>/montoya-api-<VERSION>.jar
```

To find the right `<VERSION>`, check your Burp install: `net.portswigger.burp.extensions.montoya-api`
in the Extensions output, or the [Burp Montoya API releases](https://github.com/PortSwigger/montoya-api/releases).
Then recompile with that jar:

```bash
curl -L -o /tmp/montoya-api.jar \
  https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/<VERSION>/montoya-api-<VERSION>.jar
sh build.sh /tmp/montoya-api.jar
```

---

## Install in Burp

1. Open Burp Suite.
2. Go to the **Extensions** tab.
3. Click **Add** (on the *Installed* sub-tab).
4. Set **Extension type** to `Java`.
5. Click **Select file** and choose `dist/java-object-modify-0.1.0.jar`.
6. Click **Next**.

The output console should show:

```
Java Object Modify loaded (Montoya API).
```

The tab appears per-editor, so it is registered when you open Repeater/Proxy;
you do not need to restart Burp.

---

## Usage

### 1. Open a message with a serialized object

Send a request (or intercept one in Proxy) whose message contains a Java
serialized stream — for example a base64 cookie:

```http
GET / HTTP/1.1
Host: localhost:8080
Cookie: role=rO0ABXNyACFjb20ubGFi...dAAFZ3Vlc3Q=
```

### 2. Switch to the tab

At the bottom of the request editor, click the **Java Object Modify** tab.
The main panel shows:

- a **tree** of the decoded object graph (left),
- an **edit card** for the selected value (right),
- a **toolbar** with object index, auto-apply toggle, **Apply edits** button,
  and theme selector,
- a **status bar** with request/response badge, object count, stream offset,
  base64/raw indicator, and message size.

### 3. Edit a value

1. Expand the tree and click a scalar value (e.g. `username`).
2. Type the new value in the edit card.
   - **Auto-apply on (default):** the message updates on every keystroke.
   - **Auto-apply off:** press **Apply edits** to commit your changes.
3. Send the request from Repeater — the outgoing cookie/body contains the
   modified serialized stream.

> Example: changing `username` from `user` to `admin` in the cookie above
> produces a new, clean base64 token (single valid token, proper `==` padding).

### 4. Multi-object streams

If the stream contains several top-level `writeObject()` calls, enter the
0-based index in the **Object index** field to switch which object the tree shows.

---

## Themes

The toolbar includes a **Theme** selector:

- **Light** — default light palette
- **Dark** — dark panels, light text, adjusted accent/type colors
- **System** — follows Burp's current look-and-feel (Detects Darcula)

The choice is stored in Burp preferences (`java_object_modify.theme`) and
restored on the next session.

---

## Project layout

```
.
├── build.sh                         # one-shot build script
├── src/
│   ├── javaser/
│   │   └── JavaSerializationProtocol.java   # serialization parser + encoder (no deps)
│   └── burp/
│       ├── javaobjectmodify/
│       │   └── JavaObjectModifyExtension.java  # Burp extension, tab UI, themes
│       └── META-INF/
│           └── services/burp.api.extension.BurpExtension  # service descriptor
└── dist/
    └── java-object-modify-0.1.0.jar  # prebuilt extension
```

- **`JavaSerializationProtocol.java`** — standalone protocol engine. Parses the
  binary stream into `SObject` / `SArray` / `SString` / … nodes with per-instance
  field values, and re-encodes them with an identity-based handle table so
  references and cycles are preserved.
- **`JavaObjectModifyExtension.java`** — Montoya wiring, stream location
  (raw/base64), tree renderer, edit card, theme palettes, and the splice-back logic.

---

## Known limitations

- **Byte-identity:** the encoder re-emits field-type signature strings as fresh
  `TC_STRING`s instead of sharing them, so re-serialized bytes can differ from the
  original. The result still **deserializes identically** in the JDK.
- **Binary blocks:** `writeObject()` block data is captured as opaque bytes and
  replayed verbatim — it is displayed but not editable at the field level.
- **Some JDK `readResolve`/`readObject` semantics** are preserved through raw
  annotation bytes, but the tab itself never invokes runtime deserialization.
- Invalid/truncated streams are reported in the status bar rather than shown.

---

## Troubleshooting

### The tab does not appear

- The message must contain a serialized stream: raw `AC ED` bytes **or** a base64
  token that decodes to `AC ED`. Check your message for:
  - a `Cookie:` / header containing long base64 (`rO0...`)
  - a body starting with `AC ED`
- The token must be **valid base64 with correct padding**. A corrupted cookie
  (e.g. ending in `====`) will not be recognized — restore the original token first.
- Verify the extension loaded: check **Extensions → Installed** and the *Output*
  / *Errors* console for `Java Object Modify loaded (Montoya API).`
- If you see `UnsupportedClassVersionError` or `NoClassDefFoundError:
  burp.api.montoya...`, your Burp is too old for the compiled Montoya API —
  recompile against your Burp's API version (see [Compile](#compile-from-source)).

### Edits don't stick

- Make sure you're on the **Java Object Modify** tab when sending, or that
  auto-apply already updated the message back into the editor.
- If **Auto-apply edits** is unchecked, click **Apply edits** before sending.

### I broke my cookie with trailing `=`

Reset it to the original value (restore from your proxy history / the server's
set-cookie), then re-open the tab. Repeated edits no longer accumulate padding —
the entire token (including `=` padding) is replaced on every apply.

---

## License

MIT — use it, modify it, share it. This project is not affiliated with
PortSwigger or Burp Suite.
