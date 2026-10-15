package javaser;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Tolerant binary parser/serializer for the Java Object Serialization stream
 * format (Java Object Serialization Specification, Section 6).
 *
 * <p>The decoder produces a tree of {@code SNode}s; the encoder re-serializes
 * that tree using an identity-based handle table so that interior object
 * references (including cycles) are preserved. Block-data annotations left by
 * custom {@code writeObject} methods are kept as opaque bytes and replayed
 * verbatim.
 *
 * <p>Supported content: TC_NULL, TC_REFERENCE, TC_CLASSDESC,
 * TC_PROXYCLASSDESC, TC_OBJECT, TC_STRING, TC_LONGSTRING, TC_ARRAY, TC_CLASS,
 * TC_ENUM, TC_BLOCKDATA, TC_BLOCKDATALONG, TC_ENDBLOCKDATA, TC_RESET.
 */
public final class JavaSerializationProtocol {

    /** Content type constants from the serialization spec. */
    public static final int TC_NULL = 0x70;
    public static final int TC_REFERENCE = 0x71;
    public static final int TC_CLASSDESC = 0x72;
    public static final int TC_OBJECT = 0x73;
    public static final int TC_STRING = 0x74;
    public static final int TC_ARRAY = 0x75;
    public static final int TC_CLASS = 0x76;
    public static final int TC_BLOCKDATA = 0x77;
    public static final int TC_ENDBLOCKDATA = 0x78;
    public static final int TC_RESET = 0x79;
    public static final int TC_BLOCKDATALONG = 0x7A;
    public static final int TC_EXCEPTION = 0x7B;
    public static final int TC_LONGSTRING = 0x7C;
    public static final int TC_PROXYCLASSDESC = 0x7D;
    public static final int TC_ENUM = 0x7E;

    public static final int BASE_WIRE_HANDLE = 0x7E0000;
    public static final int SC_WRITE_METHOD = 0x01;
    public static final int SC_BLOCK_DATA = 0x08;

    private JavaSerializationProtocol() {
    }

    // ------------------------------------------------------------------
    // Node model
    // ------------------------------------------------------------------

    public abstract static class SNode {
        public abstract String describe();
    }

    public static final class SNull extends SNode {
        public static final SNull INSTANCE = new SNull();
        private SNull() { }
        public String describe() { return "null"; }
    }

    public static final class SString extends SNode {
        public String value;
        private boolean wrappedUserEdit;

        public SString(String value) { this.value = value == null ? "" : value; }
        public String describe() { return "\"" + value + "\""; }
    }

    public static final class SBlockData extends SNode {
        public final byte[] raw;
        public SBlockData(byte[] raw) { this.raw = raw; }
        public String describe() { return "blockData[" + raw.length + "]"; }
    }

    public static final class SRef extends SNode {
        public final SNode target;
        public SRef(SNode target) { this.target = target; }
        public String describe() { return "ref->" + (target == null ? "null" : target.describe()); }
    }

    public static final class SField {
        public final char type;
        public final String name;
        public final String signature;   // for 'L' / '['
        /** When the wire wrote the field type as previousClassDesc. */
        public SClassDesc refClassDesc;
        /** When the wire wrote the field type as a reference to a sig string. */
        public SString refSigString;
        public Object value;             // boxed primitive or SNode
        public boolean edited;

        public SField(char type, String name, String signature) {
            this.type = type;
            this.name = name;
            this.signature = signature;
        }
    }

    public static final class SClassDesc extends SNode {
        public String className = "";
        public long serialVersionUID;
        public int flags;
        public final List<SField> fields = new ArrayList<>();
        public final List<byte[]> annotationBlocks = new ArrayList<>();
        public boolean proxy;
        public String[] proxyInterfaces = new String[0];
        public SClassDesc superDesc;
        /**
         * True only for the synthetic "no superclass" note that terminates a
         * class chain. Never set on a real class descriptor.
         */
        public boolean nullSuper;

        public boolean hasWriteMethod() { return (flags & SC_WRITE_METHOD) != 0; }
        public boolean hasBlockData() { return (flags & SC_BLOCK_DATA) != 0; }
        public String describe() {
            return proxy ? "proxyClassDesc(" + String.join(",", proxyInterfaces) + ")"
                    : "classDesc(" + className + ")";
        }
    }

    public static final class SObject extends SNode {
        public final SClassDesc desc;
        public boolean isEnum;
        /** Field values owned by this object instance (desc fields are shared). */
        public final Map<String, Object> values = new LinkedHashMap<>();
        /** Creation order, used to unify repeated nodes at encode time. */
        public int seq;
        /** True when the topmost classdesc has a TC_NULL super-slot (normal). */
        public boolean chainEnded;
        public String enumName;          // only for enums
        public final List<Object> annotationData = new ArrayList<>();

        public SObject(SClassDesc desc) { this.desc = desc; }

        public List<SField> fieldsInWireOrder() {
            List<SField> out = new ArrayList<>();
            List<SClassDesc> chain = classChain();
            for (int i = chain.size() - 1; i >= 0; i--) {
                SClassDesc d = chain.get(i);
                if (d != null && !d.proxy && !d.nullSuper) out.addAll(d.fields);
            }
            return out;
        }

        public List<SClassDesc> classChain() {
            List<SClassDesc> chain = new ArrayList<>();
            for (SClassDesc d = desc; d != null && !d.nullSuper; d = d.superDesc) {
                chain.add(d);
            }
            return chain;
        }

        public SField findField(String name) {
            for (SField f : fieldsInWireOrder()) {
                if (f.name.equals(name)) return f;
            }
            return null;
        }

        /** The edited value for a field name, or the desc's stored value. */
        public Object fieldValue(String name) {
            if (values.containsKey(name)) return values.get(name);
            SField f = findField(name);
            return f == null ? null : f.value;
        }

        public void setFieldValue(String name, Object v) {
            values.put(name, v);
            SField f = findField(name);
            if (f != null) f.edited = true;
        }

        public boolean hasWriteMethod() {
            for (SClassDesc d : classChain()) {
                if (d != null && d.hasWriteMethod()) return true;
            }
            return false;
        }

        public String describe() {
            return isEnum ? "enum(" + (desc == null ? "?" : desc.className) + ")"
                    : "object(" + (desc == null ? "?" : desc.className) + ")";
        }
    }

    public static final class SArray extends SNode {
        public SClassDesc arrayDesc;
        public final List<Object> values = new ArrayList<>();
        public int declaredLength;

        /** Element type code derived from the array class name ("[I" -> 'I'). */
        public char elementType() {
            if (arrayDesc == null || arrayDesc.className == null) return 'L';
            String cn = arrayDesc.className;
            if (cn.startsWith("[")) cn = cn.substring(1);
            if (cn.length() == 1) return cn.charAt(0);
            if (cn.startsWith("L")) return 'L';
            return 'L';
        }

        public String describe() { return "array[" + values.size() + "]"; }
    }

    public static final class SClass extends SNode {
        public final SClassDesc desc;
        public SClass(SClassDesc desc) { this.desc = desc; }
        public String describe() { return "class(" + (desc == null ? "?" : desc.className) + ")"; }
    }

    // ------------------------------------------------------------------
    // Result types
    // ------------------------------------------------------------------

    public static final class ParseResult {
        public final String error;
        public final List<Object> topLevels; // SNode roots
        public final int consumed;

        public ParseResult(String error, List<Object> topLevels, int consumed) {
            this.error = error;
            this.topLevels = topLevels;
            this.consumed = consumed;
        }

        public boolean ok() { return error == null; }
    }

    public static final class EncodeResult {
        public final String error;
        public final byte[] bytes;

        public EncodeResult(String error, byte[] bytes) {
            this.error = error;
            this.bytes = bytes;
        }

        public boolean ok() { return error == null; }
    }

    public static String typeName(char t) {
        switch (t) {
            case 'B': return "byte";
            case 'C': return "char";
            case 'D': return "double";
            case 'F': return "float";
            case 'I': return "int";
            case 'J': return "long";
            case 'S': return "short";
            case 'Z': return "boolean";
            case 'L': return "Object";
            case '[': return "Array";
            default: return String.format("0x%02X", t & 0xFF);
        }
    }

    // ------------------------------------------------------------------
    // Decoder
    // ------------------------------------------------------------------

    public static ParseResult parse(byte[] data) {
        if (data == null || data.length < 2 || (data[0] & 0xFF) != 0xAC || (data[1] & 0xFF) != 0xED) {
            return new ParseResult("Not a Java serialization stream (missing AC ED magic)", null, 0);
        }
        Reader r = new Reader(data);
        try {
            r.u1(); r.u1(); // magic (validated above)
            r.u2();          // version
            List<Object> roots = new ArrayList<>();
            while (r.remaining() > 0) {
                int b = r.peek();
                if (b == TC_RESET) {
                    r.u1();
                    r.handles.clear();
                    continue;
                }
                roots.add(r.readNode());
            }
            return new ParseResult(null, roots, r.pos);
        } catch (EOFException eof) {
            return new ParseResult("Stream truncated at offset " + r.pos, null, r.pos);
        } catch (IOException ioe) {
            String msg = ioe.getMessage();
            return new ParseResult(msg == null ? ioe.getClass().getSimpleName() : msg, null, r.pos);
        }
    }

    private static final class Reader {
        final byte[] b;
        int pos;
        final List<SNode> handles = new ArrayList<>();
        int nextObjSeq = 0;
        /** Maps a classdesc to the FIRST object we built for it (for interning). */
        final java.util.IdentityHashMap<SClassDesc, SObject> firstObjectOfDesc = new java.util.IdentityHashMap<>();
        /** Singleton synthetic TC_NULL super-slot marker. */
        private static final SClassDesc NULL_SUPER = makeNullSuper();

        private static SClassDesc makeNullSuper() {
            SClassDesc d = new SClassDesc();
            d.nullSuper = true;
            return d;
        }

        Reader(byte[] b) { this.b = b; }

        int remaining() throws IOException {
            if (pos > b.length) throw new EOFException();
            return b.length - pos;
        }

        int peek() throws IOException {
            if (pos >= b.length) throw new EOFException("expected byte at " + pos);
            return b[pos] & 0xFF;
        }

        int u1() throws IOException {
            if (pos >= b.length) throw new EOFException("expected byte at " + pos);
            return b[pos++] & 0xFF;
        }

        int u2() throws IOException {
            if (pos + 2 > b.length) throw new EOFException("expected short at " + pos);
            int v = ((b[pos] & 0xFF) << 8) | (b[pos + 1] & 0xFF);
            pos += 2;
            return v;
        }

        int u4() throws IOException {
            if (pos + 4 > b.length) throw new EOFException("expected int at " + pos);
            int v = ((b[pos] & 0xFF) << 24) | ((b[pos + 1] & 0xFF) << 16)
                    | ((b[pos + 2] & 0xFF) << 8) | (b[pos + 3] & 0xFF);
            pos += 4;
            return v;
        }

        long s8() throws IOException {
            long v = 0;
            for (int i = 0; i < 8; i++) v = (v << 8) | u1();
            return v;
        }

        int peek4() throws IOException {
            check(4);
            return ((b[pos] & 0xFF) << 24) | ((b[pos + 1] & 0xFF) << 16)
                    | ((b[pos + 2] & 0xFF) << 8) | (b[pos + 3] & 0xFF);
        }

        void check(int n) throws IOException {
            if (pos + n > b.length) throw new EOFException("expected " + n + " bytes at " + pos);
        }

        String utf() throws IOException { return new String(read(u2()), StandardCharsets.UTF_8); }
        String longUtf() throws IOException { return new String(read(u4()), StandardCharsets.UTF_8); }

        byte[] read(int n) throws IOException {
            check(n);
            byte[] out = new byte[n];
            System.arraycopy(b, pos, out, 0, n);
            pos += n;
            return out;
        }

        int addHandle(SNode n) {
            handles.add(n);
            return BASE_WIRE_HANDLE + handles.size() - 1;
        }

        SNode resolve(int h) throws IOException {
            int idx = h - BASE_WIRE_HANDLE;
            if (idx < 0 || idx >= handles.size()) {
                throw new IOException("bad handle 0x" + Integer.toHexString(h) + " at offset " + (pos - 4));
            }
            return handles.get(idx);
        }

        /** Reads a full content value including its tag. */
        SNode readNode() throws IOException {
            int tc = u1();
            return content(tc);
        }

        // ---- content decoding ----

        /** Reads one content value; the tag has already been consumed. */
        SNode content(int tc) throws IOException {
            switch (tc) {
                case TC_NULL: return SNull.INSTANCE;
                case TC_REFERENCE: {
                    int h = u4();
                    int idx = h - BASE_WIRE_HANDLE;
                    if (idx < 0 || idx >= handles.size()) {
                        throw new IOException("bad handle 0x" + Integer.toHexString(h) + " at offset " + (pos - 4));
                    }
                    return new SRef(handles.get(idx));
                }
                case TC_STRING: case TC_LONGSTRING: {
                    SString s = new SString(tc == TC_LONGSTRING ? longUtf() : utf());
                    addHandle(s);
                    return s;
                }
                case TC_CLASSDESC: return readClassDesc();
                case TC_PROXYCLASSDESC: return readProxyClassDesc();
                case TC_OBJECT: return readObject(null, false);
                case TC_ARRAY: return readArray();
                case TC_CLASS: {
                    SClassDesc d = readClassDesc();
                    addHandle(new MarkerNode("class"));
                    return new SClass(d);
                }
                case TC_ENUM: return readEnum();
                case TC_BLOCKDATA: return new SBlockData(read(u1()));
                case TC_BLOCKDATALONG: return new SBlockData(read(u4()));
                case TC_ENDBLOCKDATA: throw new IOException("unexpected TC_ENDBLOCKDATA at offset " + (pos - 1));
                case TC_RESET:
                    handles.clear();
                    return SNull.INSTANCE;
                case TC_EXCEPTION:
                    throw new IOException("stream contains TC_EXCEPTION (writeObject failed) at offset " + (pos - 1));
                default:
                    throw new IOException(String.format("unsupported content tag 0x%02X at offset %d", tc & 0xFF, pos - 1));
            }
        }

        /**
         * Reads a class descriptor including its leading tag. Supports
         * TC_CLASSDESC (inline), TC_PROXYCLASSDESC, TC_REFERENCE
         * (previousClassDesc), and TC_NULL (for the null-superclass slot).
         */
        SClassDesc readClassDesc() throws IOException {
            int tag = u1();
            switch (tag) {
                case TC_NULL: {
                    return NULL_SUPER;
                }
                case TC_REFERENCE: {
                    int h = u4();
                    int idx = h - BASE_WIRE_HANDLE;
                    if (idx < 0 || idx >= handles.size() || !(handles.get(idx) instanceof SClassDesc)) {
                        throw new IOException("previous class descriptor does not resolve to a class descriptor: 0x"
                                + Integer.toHexString(h) + " at offset " + (pos - 4));
                    }
                    return (SClassDesc) handles.get(idx);
                }
                case TC_CLASSDESC: return readFullClassDesc();
                case TC_PROXYCLASSDESC: return readProxyClassDesc();
                default:
                    throw new IOException("unexpected class descriptor tag 0x" + Integer.toHexString(tag) + " at " + (pos - 1));
            }
        }

        SClassDesc readFullClassDesc() throws IOException {
            SClassDesc d = new SClassDesc();
            d.className = utf();
            d.serialVersionUID = s8();
            d.flags = u1();
            int nfields = u2();
            // JDK writeNonProxyDesc assigns the descriptor handle right after
            // flags/field-count, BEFORE the field type strings (each of which
            // also takes a handle).
            addHandle(d);
            for (int i = 0; i < nfields; i++) {
                char type = (char) u1();
                String name = utf();
                String sig = null;
                SClassDesc refDesc = null;
                SString refSig = null;
                if (type == 'L' || type == '[') {
                    int sigTag = u1();
                    if (sigTag == TC_STRING || sigTag == TC_LONGSTRING) {
                        sig = (sigTag == TC_LONGSTRING) ? longUtf() : utf();
                        addHandle(new SString(sig));
                    } else if (sigTag == TC_REFERENCE) {
                        int h = u4();
                        SNode target = resolve(h);
                        if (target instanceof SString) {
                            sig = ((SString) target).value;
                            refSig = (SString) target;
                        } else if (target instanceof SClassDesc) {
                            String cn = ((SClassDesc) target).className;
                            sig = cn.startsWith("L") && cn.endsWith(";") ? cn : "L" + cn + ";";
                            refDesc = (SClassDesc) target;
                        } else {
                            throw new IOException("field-signature reference does not point at a string at " + (pos - 4));
                        }
                    } else if (sigTag == TC_NULL) {
                        sig = null;
                    } else {
                        // Legacy JDKs wrote the signature via plain writeUTF.
                        pos -= 1;
                        sig = utf();
                    }
                }
                SField f = new SField(type, name, sig);
                f.refClassDesc = refDesc;
                f.refSigString = refSig;
                d.fields.add(f);
            }
            // class annotation: block-data content
            while (true) {
                int t = peek();
                if (t == TC_ENDBLOCKDATA) { u1(); break; }
                else if (t == TC_BLOCKDATA) { u1(); d.annotationBlocks.add(read(u1())); }
                else if (t == TC_BLOCKDATALONG) { u1(); d.annotationBlocks.add(read(u4())); }
                else throw new IOException("unexpected class-annotation tag 0x" + Integer.toHexString(t) + " at " + pos);
            }
            // superclass descriptor: NULL for a missing super, otherwise
            // TC_CLASSDESC/TC_PROXYCLASSDESC/TC_REFERENCE.
            readSuperInto(d);
            return d;
        }

        void readSuperInto(SClassDesc d) throws IOException {
            int st = peek();
            if (st == TC_NULL) {
                u1();
                d.superDesc = NULL_SUPER;
                return;
            }
            d.superDesc = readClassDesc();
        }

        SClassDesc readProxyClassDesc() throws IOException {
            SClassDesc d = new SClassDesc();
            d.proxy = true;
            int n = u4();
            String[] ifaces = new String[n];
            for (int i = 0; i < n; i++) ifaces[i] = utf();
            d.proxyInterfaces = ifaces;
            int t = u1();
            if (t != TC_ENDBLOCKDATA) {
                throw new IOException("expected TC_ENDBLOCKDATA after proxy interfaces at " + (pos - 1));
            }
            addHandle(d);
            return d;
        }

        SObject readObject(SClassDesc forced, boolean enumForm) throws IOException {
            SClassDesc d = forced != null ? forced : readClassDesc();
            SObject obj = new SObject(d);
            obj.isEnum = enumForm;
            obj.seq = nextObjSeq++;
            obj.chainEnded = d.nullSuper;
            if (!enumForm) addHandle(obj);
            if (enumForm) {
                int t = u1();
                if (t == TC_STRING || t == TC_LONGSTRING) {
                    obj.enumName = t == TC_LONGSTRING ? longUtf() : utf();
                    addHandle(new MarkerNode("enumname"));
                } else if (t == TC_NULL) {
                    obj.enumName = null;
                } else {
                    throw new IOException("unexpected enum constant tag 0x" + Integer.toHexString(t) + " at " + (pos - 1));
                }
                return obj;
            }
            List<SClassDesc> chain = obj.classChain();
            for (SClassDesc cd : chain) {
                readFieldsInto(obj, cd);
            }
            if (obj.hasWriteMethod()) {
                readObjectAnnotation(obj);
            }
            return obj;
        }

        /** Value-level intern for objects without custom writeObject. */
        SObject internObject(SObject obj) {
            SObject prior = firstObjectOfDesc.get(obj.desc);
            if (prior != null && !prior.isEnum && !obj.isEnum) {
                return prior;
            }
            firstObjectOfDesc.put(obj.desc, obj);
            return obj;
        }

        void readFieldsInto(SObject obj, SClassDesc d) throws IOException {
            for (SField f : d.fields) {
                obj.values.put(f.name, readFieldValue(f));
            }
        }

        Object readFieldValue(SField f) throws IOException {
            switch (f.type) {
                case 'B': return u1();
                case 'C': return (char) u2();
                case 'D': return Double.longBitsToDouble(s8());
                case 'F': return Float.intBitsToFloat(u4());
                case 'I': return u4();
                case 'J': return s8();
                case 'S': return (short) u2();
                case 'Z': return u1() != 0;
                case 'L': case '[': return readNode();
                default: throw new IOException("unknown field type '" + f.type + "' at " + (pos - 1));
            }
        }

        void readObjectAnnotation(SObject obj) throws IOException {
            while (true) {
                int t = peek();
                if (t == TC_ENDBLOCKDATA) { u1(); return; }
                obj.annotationData.add(readNode());
            }
        }

        SArray readArray() throws IOException {
            SClassDesc desc = readClassDesc();
            int len = u4();
            SArray arr = new SArray();
            arr.arrayDesc = desc;
            arr.declaredLength = len;
            addHandle(arr);
            char et = arr.elementType();
            for (int i = 0; i < len; i++) {
                if (isPrimitive(et)) arr.values.add(readPrimitiveArrayElement(et));
                else arr.values.add(readNode());
            }
            return arr;
        }

        Object readPrimitiveArrayElement(char t) throws IOException {
            switch (t) {
                case 'B': return u1();
                case 'C': return (char) u2();
                case 'D': return Double.longBitsToDouble(s8());
                case 'F': return Float.intBitsToFloat(u4());
                case 'I': return u4();
                case 'J': return s8();
                case 'S': return (short) u2();
                case 'Z': return u1() != 0;
                default: throw new IOException("bad primitive type " + t);
            }
        }

        SObject readEnum() throws IOException {
            return readObject(null, true);
        }
    }

    /** Internal marker node used only to advance handle indices. */
    private static final class MarkerNode extends SNode {
        MarkerNode(String s) { }
        public String describe() { return "marker"; }
    }

    // ------------------------------------------------------------------
    // Encoder
    // ------------------------------------------------------------------

    public static EncodeResult encode(List<Object> topLevels) {
        if (topLevels == null || topLevels.isEmpty()) {
            return new EncodeResult("No objects to encode", null);
        }
        try {
            Writer w = new Writer();
            w.u1(0xAC);
            w.u1(0xED);
            w.u2(0x0005);
            for (Object o : topLevels) {
                w.writeNode((SNode) o);
            }
            return new EncodeResult(null, w.toByteArray());
        } catch (IOException | RuntimeException exc) {
            String msg = exc.getMessage();
            return new EncodeResult(msg == null ? exc.getClass().getSimpleName() : msg, null);
        }
    }

    private static final class Writer {
        final ByteArrayOutputStream out = new ByteArrayOutputStream(4096);
        final IdentityHashMap<SNode, Integer> handles = new IdentityHashMap<>();
        final Map<String, Integer> writtenSigs = new java.util.HashMap<>();
        final Map<String, SClassDesc> writtenDescs = new java.util.HashMap<>();

        void u1(int v) { out.write(v & 0xFF); }
        void u2(int v) { out.write((v >>> 8) & 0xFF); out.write(v & 0xFF); }
        void u4(int v) {
            out.write((v >>> 24) & 0xFF);
            out.write((v >>> 16) & 0xFF);
            out.write((v >>> 8) & 0xFF);
            out.write(v & 0xFF);
        }
        void s8(long v) {
            for (int i = 7; i >= 0; i--) out.write((int) ((v >>> (i * 8)) & 0xFF));
        }
        void utf(String s) {
            if (s == null) s = "";
            byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
            u2(bytes.length);
            out.write(bytes, 0, bytes.length);
        }

        int assign(SNode n) {
            int next = BASE_WIRE_HANDLE + handles.size();
            handles.put(n, next);
            return next;
        }

        boolean already(SNode n) { return handles.containsKey(n); }

        void writeNode(SNode n) throws IOException {
            if (n instanceof SNull) { u1(TC_NULL); return; }
            if (n instanceof SRef) {
                SRef r = (SRef) n;
                Integer h = handles.get(r.target);
                if (h != null) {
                    u1(TC_REFERENCE);
                    u4(h);
                    return;
                }
                // Forward reference to a not-yet-written node: duplicate it
                // inline (semantically equal, avoids invalid back-refs).
                writeNode(r.target);
                return;
            }
            if (n instanceof SString) {
                SString s = (SString) n;
                if (already(s)) { u1(TC_REFERENCE); u4(handles.get(s)); return; }
                u1(TC_STRING);
                utf(s.value);
                assign(s);
                return;
            }
            if (n instanceof SBlockData) {
                SBlockData bd = (SBlockData) n;
                if (bd.raw.length < 256) { u1(TC_BLOCKDATA); u1(bd.raw.length); }
                else { u1(TC_BLOCKDATALONG); u4(bd.raw.length); }
                out.write(bd.raw, 0, bd.raw.length);
                return;
            }
            if (n instanceof SObject) { writeObject((SObject) n); return; }
            if (n instanceof SArray) { writeArray((SArray) n); return; }
            if (n instanceof SClass) {
                SClass c = (SClass) n;
                u1(TC_CLASS);
                writeClassDesc(c.desc);
                if (!already(c)) assign(c);
                return;
            }
            if (n instanceof MarkerNode) { /* never serialized */ return; }
            throw new IOException("cannot encode node type " + n.getClass().getSimpleName());
        }

        void writeObject(SObject obj) throws IOException {
            if (already(obj)) { u1(TC_REFERENCE); u4(handles.get(obj)); return; }
            u1(obj.isEnum ? TC_ENUM : TC_OBJECT);
            writeClassDesc(obj.desc);
            if (!obj.isEnum) assign(obj);
            if (obj.isEnum) {
                if (obj.enumName == null) { u1(TC_NULL); }
                else { u1(TC_STRING); utf(obj.enumName); assign(new MarkerNode("enumname")); }
                return;
            }
            List<SClassDesc> chain = obj.classChain();
            for (SClassDesc cd : chain) writeObjectFields(obj, cd);
            if (obj.hasWriteMethod()) {
                writeObjectAnnotation(obj);
            }
        }

        void writeObjectFields(SObject obj, SClassDesc cd) throws IOException {
            for (SField f : cd.fields) {
                SField tmp = new SField(f.type, f.name, f.signature);
                tmp.value = obj.fieldValue(f.name);
                tmp.refSigString = f.refSigString;
                tmp.refClassDesc = f.refClassDesc;
                writeFieldValue(tmp);
            }
        }


        void writeObjectAnnotation(SObject obj) throws IOException {
            for (Object o : obj.annotationData) {
                if (o instanceof SNode) writeNode((SNode) o);
            }
            u1(TC_ENDBLOCKDATA);
        }

        void writeFieldValue(SField f) throws IOException {
            Object v = f.value;
            switch (f.type) {
                case 'B': u1(coerceNumber(v, 0).intValue() & 0xFF); return;
                case 'C': u2(coerceNumber(v, 0).intValue() & 0xFFFF); return;
                case 'D': s8(Double.doubleToLongBits(coerceNumber(v, 0.0).doubleValue())); return;
                case 'F': u4(Float.floatToIntBits(coerceNumber(v, 0f).floatValue())); return;
                case 'I': u4(coerceNumber(v, 0).intValue()); return;
                case 'J': s8(coerceNumber(v, 0L).longValue()); return;
                case 'S': u2(coerceNumber(v, 0).shortValue() & 0xFFFF); return;
                case 'Z': u1(coerceBoolean(v)); return;
                case 'L': case '[':
                    if (v == null || v == SNull.INSTANCE) { u1(TC_NULL); return; }
                    if (v instanceof SNode) {
                        if (already((SNode) v)) {
                            u1(TC_REFERENCE);
                            u4(handles.get((SNode) v));
                        } else {
                            writeNode((SNode) v);
                        }
                        return;
                    }
                    SString s = new SString(String.valueOf(v));
                    u1(TC_STRING);
                    utf(s.value);
                    assign(s);
                    return;
                default: throw new IOException("unknown field type '" + f.type + "'");
            }
        }

        static String stripSig(String sig) {
            if (sig == null) return "";
            if (sig.startsWith("L") && sig.endsWith(";")) {
                return sig.substring(1, sig.length() - 1);
            }
            return sig;
        }

        static boolean previousClassDescAliasOK(SClassDesc d) { return true; }

        Number coerceNumber(Object v, Number dflt) {
            if (v == null) return dflt;
            if (v instanceof Number) return (Number) v;
            try {
                String s = String.valueOf(v).trim();
                if (s.isEmpty()) return dflt;
                return parseNum(s);
            } catch (NumberFormatException nfe) {
                return dflt;
            }
        }

        Number parseNum(String s) throws NumberFormatException {
            if (s.matches("[-+]?\\d+")) return Long.decode(s);
            if (s.matches("[-+]?0[xX][0-9a-fA-F]+")) return Long.decode(s);
            return Double.parseDouble(s);
        }

        int coerceBoolean(Object v) {
            if (v == null) return 0;
            if (v instanceof Boolean) return ((Boolean) v) ? 1 : 0;
            String s = String.valueOf(v).trim().toLowerCase();
            return (s.equals("true") || s.equals("1") || s.equals("yes") || s.equals("on")) ? 1 : 0;
        }

        void writeArray(SArray arr) throws IOException {
            if (already(arr)) { u1(TC_REFERENCE); u4(handles.get(arr)); return; }
            u1(TC_ARRAY);
            writeClassDesc(arr.arrayDesc);
            assign(arr);
            int len = Math.min(arr.declaredLength, arr.values.size());
            u4(len);
            char et = arr.elementType();
            for (int i = 0; i < len; i++) {
                Object v = arr.values.get(i);
                if (isPrimitive(et)) {
                    writePrimitiveArrayElement(et, v);
                } else if (v instanceof SNode) {
                    writeNode((SNode) v);
                } else {
                    u1(TC_NULL);
                }
            }
        }

        void writePrimitiveArrayElement(char t, Object v) throws IOException {
            switch (t) {
                case 'B': u1(coerceNumber(v, 0).intValue() & 0xFF); return;
                case 'C': u2(coerceNumber(v, 0).intValue() & 0xFFFF); return;
                case 'D': s8(Double.doubleToLongBits(coerceNumber(v, 0.0).doubleValue())); return;
                case 'F': u4(Float.floatToIntBits(coerceNumber(v, 0f).floatValue())); return;
                case 'I': u4(coerceNumber(v, 0).intValue()); return;
                case 'J': s8(coerceNumber(v, 0L).longValue()); return;
                case 'S': u2(coerceNumber(v, 0).shortValue() & 0xFFFF); return;
                case 'Z': u1(coerceBoolean(v)); return;
                default: throw new IOException("bad primitive type " + t);
            }
        }

        SClassDesc writeClassDesc(SClassDesc d) throws IOException {
            if (d == null || d.nullSuper) { u1(TC_NULL); return d; }
            // d is a real descriptor; if we've already seen it, use previousClassDesc.
            if (already(d)) { u1(TC_REFERENCE); u4(handles.get(d)); return d; }
            if (d.proxy) {
                u1(TC_PROXYCLASSDESC);
                u4(d.proxyInterfaces.length);
                for (String s : d.proxyInterfaces) utf(s);
                u1(TC_ENDBLOCKDATA);
                assign(d);
                return d;
            }
            u1(TC_CLASSDESC);
            utf(d.className);
            s8(d.serialVersionUID);
            u1(d.flags);
            u2(d.fields.size());
            writtenDescs.put(d.className, d);
            // Descriptor handle assigned before field type strings.
            assign(d);
            for (SField f : d.fields) {
                u1(f.type);
                utf(f.name);
                if (f.type == 'L' || f.type == '[') {
                    // Always emit a fresh TC_STRING for the field type. This is
                    // always valid at the wire level (the JDK may share strings
                    // across descriptors, but re-writing is semantically equal).
                    String sig = f.signature == null ? "" : f.signature;
                    u1(TC_STRING);
                    utf(sig);
                    assign(new MarkerNode("fieldtype"));
                }
            }
            for (byte[] block : d.annotationBlocks) {
                if (block.length < 256) { u1(TC_BLOCKDATA); u1(block.length); }
                else { u1(TC_BLOCKDATALONG); u4(block.length); }
                out.write(block, 0, block.length);
            }
            u1(TC_ENDBLOCKDATA);
            if (d.superDesc == null || d.superDesc.nullSuper) u1(TC_NULL);
            else writeClassDesc(d.superDesc);
            return d;
        }

        byte[] toByteArray() { return out.toByteArray(); }
    }

    static boolean isPrimitive(char t) {
        return t == 'B' || t == 'C' || t == 'D' || t == 'F' || t == 'I'
                || t == 'J' || t == 'S' || t == 'Z';
    }

    // ------------------------------------------------------------------
    // Tree helpers for the UI
    // ------------------------------------------------------------------

    /**
     * Builds a flat list of (path, label, editable) entries for the tree
     * panel, mirroring the wire structure.
     */
    public static List<ValueEntry> toValueEntries(List<Object> roots) {
        List<ValueEntry> out = new ArrayList<>();
        int gi = 0;
        for (Object root : roots) {
            walk("", root, out);
        }
        return out;
    }

    public static final class ValueEntry {
        public final String path;
        public final String label;
        public final Object node;
        public final boolean editable;
        /** UI hint: which value container to update on edit. */
        public final String editTarget;

        ValueEntry(String path, String label, Object node, boolean editable, String editTarget) {
            this.path = path;
            this.label = label;
            this.node = node;
            this.editable = editable;
            this.editTarget = editTarget;
        }
    }

    private static void walk(String prefix, Object node, List<ValueEntry> out) {
        if (node instanceof SObject) {
            SObject on = (SObject) node;
            String label = on.describe();
            out.add(new ValueEntry(path(prefix), label, on, false, null));
            for (SField f : on.fieldsInWireOrder()) {
                walk(join(prefix, f.name), on.fieldValue(f.name), out);
            }
        } else if (node instanceof SArray) {
            SArray arr = (SArray) node;
            out.add(new ValueEntry(path(prefix),
                    "array<" + typeName(arr.elementType()) + ">[" + arr.values.size() + "]",
                    arr, false, null));
            int i = 0;
            for (Object o : arr.values) walk(join(prefix, "[" + i + "]"), o, out);
            // pad to declaredLength with null placeholders
            for (int k = arr.values.size(); k < arr.declaredLength; k++) {
                out.add(new ValueEntry(join(prefix, "[" + k + "]"), "null", SNull.INSTANCE, false, null));
            }
            i++;
        } else if (node instanceof SString) {
            SString s = (SString) node;
            out.add(new ValueEntry(path(prefix), "String: \"" + cut(s.value) + "\"", s, true, null));
        } else if (node instanceof SBlockData) {
            SBlockData bd = (SBlockData) node;
            out.add(new ValueEntry(path(prefix), "blockData[" + bd.raw.length + " bytes]", bd, false, null));
        } else if (node instanceof SRef) {
            out.add(new ValueEntry(path(prefix), "-> " + ((SRef) node).target.describe(), node, false, null));
        } else if (node instanceof SClass) {
            out.add(new ValueEntry(path(prefix), "class(" + ((SClass) node).desc.className + ")", node, false, null));
        } else if (node == SNull.INSTANCE || node == null) {
            out.add(new ValueEntry(path(prefix), "null", SNull.INSTANCE, false, null));
        } else if (node instanceof Boolean) {
            out.add(new ValueEntry(path(prefix), "boolean: " + node, node, true, null));
        } else if (node instanceof Number) {
            out.add(new ValueEntry(path(prefix), typeLabel(node) + ": " + node, node, true, null));
        } else if (node instanceof Character) {
            out.add(new ValueEntry(path(prefix), "char: '" + node + "'", node, true, null));
        } else {
            out.add(new ValueEntry(path(prefix), String.valueOf(node), node, true, null));
        }
    }

    private static String typeLabel(Object node) {
        if (node instanceof Byte) return "byte";
        if (node instanceof Short) return "short";
        if (node instanceof Integer) return "int";
        if (node instanceof Long) return "long";
        if (node instanceof Float) return "float";
        if (node instanceof Double) return "double";
        return "number";
    }

    private static String path(String prefix) {
        return prefix.isEmpty() ? "/" : "/" + prefix;
    }

    private static String join(String prefix, String name) {
        String safe = name.replace("/", "\\/").replace("[", "\\[").replace("]", "\\]");
        return prefix.isEmpty() ? safe : prefix + "/" + safe;
    }

    private static String cut(String s) {
        if (s == null || s.length() <= 80) return s == null ? "" : s;
        return s.substring(0, 77) + "...";
    }

    /**
     * Locate a node by its tree path (see {@code join} for escaping).
     */
    public static Object findNode(List<Object> roots, String path) {
        if (roots == null || path == null) return null;
        String p = path.startsWith("/") ? path.substring(1) : path;
        Object cur = null;
        for (Object root : roots) {
            cur = findIn(root, p);
            if (cur != null) return cur;
        }
        return null;
    }

    private static Object findIn(Object node, String path) {
        if (path.isEmpty()) return node;
        if (node instanceof SObject) {
            SObject on = (SObject) node;
            String seg = firstSeg(path);
            SField f = on.findField(unescape(seg));
            if (f == null) return null;
            return findIn(on.fieldValue(f.name), rest(path));
        }
        if (node instanceof SArray) {
            SArray arr = (SArray) node;
            String seg = firstSeg(path);
            if (seg.startsWith("[") && seg.endsWith("]")) {
                try {
                    int idx = Integer.parseInt(seg.substring(1, seg.length() - 1));
                    if (idx < 0 || idx >= arr.values.size()) return null;
                    return findIn(arr.values.get(idx), rest(path));
                } catch (NumberFormatException nfe) {
                    return null;
                }
            }
            return null;
        }
        return null;
    }

    private static String firstSeg(String path) {
        int slash = path.indexOf('/');
        return slash < 0 ? path : path.substring(0, slash);
    }

    private static String rest(String path) {
        int slash = path.indexOf('/');
        return slash < 0 ? "" : path.substring(slash + 1);
    }

    private static String unescape(String seg) {
        return seg.replace("\\/", "/").replace("\\[", "[").replace("\\]", "]");
    }

    /** Set the SNode value at the given tree path (object field or array). */
    public static void setValueAt(List<Object> roots, String path, Object newValue) {
        if (roots == null || path == null) return;
        String p = path.startsWith("/") ? path.substring(1) : path;
        for (Object root : roots) {
            if (setIn(root, p, newValue)) return;
        }
    }

    private static boolean setIn(Object node, String path, Object newValue) {
        if (path.isEmpty()) return false;
        String seg = firstSeg(path);
        String more = rest(path);
        if (node instanceof SObject) {
            SObject on = (SObject) node;
            SField f = on.findField(unescape(seg));
            if (f == null) return false;
            if (more.isEmpty()) {
                on.setFieldValue(f.name, newValue);
                return true;
            }
            return setIn(on.fieldValue(f.name), more, newValue);
        }
        if (node instanceof SArray) {
            SArray arr = (SArray) node;
            if (seg.startsWith("[") && seg.endsWith("]")) {
                try {
                    int idx = Integer.parseInt(seg.substring(1, seg.length() - 1));
                    if (idx < 0 || idx >= arr.values.size()) return false;
                    if (more.isEmpty()) {
                        arr.values.set(idx, newValue);
                        return true;
                    }
                    return setIn(arr.values.get(idx), more, newValue);
                } catch (NumberFormatException nfe) {
                    return false;
                }
            }
            return false;
        }
        return false;
    }
}
