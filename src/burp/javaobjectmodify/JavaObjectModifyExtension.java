package burp.javaobjectmodify;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import javaser.JavaSerializationProtocol;
import javaser.JavaSerializationProtocol.SArray;
import javaser.JavaSerializationProtocol.SNode;
import javaser.JavaSerializationProtocol.SNull;
import javaser.JavaSerializationProtocol.SObject;
import javaser.JavaSerializationProtocol.SString;
import javaser.JavaSerializationProtocol.ValueEntry;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeSelectionModel;
import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.RenderingHints;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Burp Suite extension (Montoya API) that adds a "Java Object Modify" editor
 * tab to Repeater, Proxy intercept, and other message editors.
 *
 * <p>The tab locates the first Java serialized object stream ({@code AC ED}
 * magic) inside the raw HTTP message, decodes it into a tree of nodes, lets
 * the user edit scalar values, and re-serializes the tree back into the
 * message. The serialization engine is implemented natively (no external
 * dependencies) so the extension also works offline.
 */
public class JavaObjectModifyExtension implements BurpExtension {

    private static final String TAB_NAME = "Java Object Modify";
    private static final byte[] MAGIC = new byte[]{(byte) 0xAC, (byte) 0xED};

    /** Theme mode: "light", "dark", or "system". */
    static volatile String themeMode = "system";
    static volatile ThemePalette palette = ThemePalette.forMode("system");

    static final class ThemePalette {
        final Color accent, accentDark, text, textMuted, panelBg, surfaceBg, border, inputBg, inputBorder;
        final Color stringC, numC, boolC, nullC, refC, danger, warn, good;

        ThemePalette(Color accent, Color accentDark, Color text, Color textMuted, Color panelBg,
                     Color surfaceBg, Color border, Color inputBg, Color inputBorder,
                     Color stringC, Color numC, Color boolC, Color nullC, Color refC,
                     Color danger, Color warn, Color good) {
            this.accent = accent; this.accentDark = accentDark;
            this.text = text; this.textMuted = textMuted;
            this.panelBg = panelBg; this.surfaceBg = surfaceBg; this.border = border;
            this.inputBg = inputBg; this.inputBorder = inputBorder;
            this.stringC = stringC; this.numC = numC; this.boolC = boolC;
            this.nullC = nullC; this.refC = refC;
            this.danger = danger; this.warn = warn; this.good = good;
        }

        static ThemePalette forMode(String mode) {
            boolean dark;
            if ("light".equals(mode)) dark = false;
            else if ("dark".equals(mode)) dark = true;
            else dark = isSystemDark();
            if (dark) {
                return new ThemePalette(
                        new Color(0x4C, 0x8D, 0xFF), new Color(0x86, 0xB1, 0xFF),
                        new Color(0xE4, 0xE4, 0xEC), new Color(0x9A, 0x9A, 0xA6),
                        new Color(0x1E, 0x1F, 0x26), new Color(0x27, 0x28, 0x30),
                        new Color(0x3A, 0x3B, 0x45), new Color(0x15, 0x16, 0x1B),
                        new Color(0x55, 0x57, 0x64),
                        new Color(0x6F, 0xC2, 0xFF), new Color(0xD7, 0x9B, 0xFF),
                        new Color(0x6F, 0xD9, 0x8B), new Color(0x7A, 0x7C, 0x88),
                        new Color(0xC7, 0xA3, 0xFF),
                        new Color(0xFF, 0x7B, 0x72), new Color(0xE2, 0xB9, 0x3C), new Color(0x7B, 0xE0, 0x94));
            }
            return new ThemePalette(
                    new Color(0x2F, 0x6F, 0xED), new Color(0x1A, 0x4F, 0xC0),
                    new Color(0x22, 0x22, 0x2A), new Color(0x8A, 0x8A, 0x95),
                    new Color(0xFB, 0xFB, 0xFD), new Color(0xFF, 0xFF, 0xFF),
                    new Color(0xE2, 0xE2, 0xEA), new Color(0xFF, 0xFF, 0xFF),
                    new Color(0xC8, 0xC8, 0xD4),
                    new Color(0x0B, 0x6E, 0x99), new Color(0x9C, 0x32, 0x95),
                    new Color(0x1E, 0x6F, 0x35), new Color(0x9A, 0x9A, 0xA2),
                    new Color(0x8B, 0x5A, 0xC8),
                    new Color(0xD4, 0x2B, 0x2B), new Color(0xC9, 0x7A, 0x00), new Color(0x1E, 0x8E, 0x3E));
        }

        static boolean isSystemDark() {
            try {
                return UIManager.getLookAndFeel() != null
                        && UIManager.getLookAndFeel().getName().toLowerCase().contains("darcula");
            } catch (Throwable t) {
                return false;
            }
        }
    }

    static Color ACCENT = palette.accent;
    static Color ACCENT_DARK = palette.accentDark;
    static Color GOOD = palette.good;
    static Color WARN = palette.warn;
    static Color DANGER = palette.danger;
    static Color STRING_C = JavaObjectModifyExtension.palette.stringC;
    static Color NUM_C = JavaObjectModifyExtension.palette.numC;
    static Color BOOL_C = JavaObjectModifyExtension.palette.boolC;
    static Color NULL_C = JavaObjectModifyExtension.palette.nullC;
    static Color PANEL_BG = palette.panelBg;

    private MontoyaApi api;
    private Logging log;

    private boolean bound = false;

    public void initialize(MontoyaApi api) {
        this.api = api;
        this.log = api.logging();

        // Let Burp's HTTP editor open this extension as a per-message editor.
        String saved = api.persistence().preferences().getString("java_object_modify.theme");
        if (saved != null && (saved.equals("light") || saved.equals("dark") || saved.equals("system"))) {
            themeMode = saved;
        } else {
            themeMode = api.userInterface().currentTheme() == burp.api.montoya.ui.Theme.DARK ? "dark" : "light";
        }
        palette = ThemePalette.forMode(themeMode);

        api.userInterface().registerHttpRequestEditorProvider(new HttpRequestEditorProvider() {
            @Override
            public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
                return new JavaObjectModifyHttpEditor(JavaObjectModifyExtension.this);
            }
        });
        api.userInterface().registerHttpResponseEditorProvider(new HttpResponseEditorProvider() {
            @Override
            public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
                return new JavaObjectModifyHttpResponseEditor(JavaObjectModifyExtension.this);
            }
        });

        log.logToOutput(TAB_NAME + " loaded (Montoya API).");
    }

    // ------------------------------------------------------------------
    // Shared tab implementation
    // ------------------------------------------------------------------

    /** The actual editor tab (used by both request and response providers). */
    static class ObjectModifyTab implements ExtensionProvidedHttpRequestEditor, ExtensionProvidedHttpResponseEditor {

        private final JavaObjectModifyExtension owner;
        private final JPanel root = new JPanel();
        private final DefaultMutableTreeNode treeRoot = new DefaultMutableTreeNode("Java Object Stream");
        private final DefaultTreeModel treeModel = new DefaultTreeModel(treeRoot);
        private final JTree tree = new JTree(treeModel);
        private final JLabel status = new JLabel("No message loaded");
        private final JLabel source = new JLabel("");
        private final JTextField indexField = new JTextField(4);
        private final JCheckBox autoApply = new JCheckBox("Auto-apply edits", true);
        private final JButton apply = new JButton("Apply edits");
        private final JPanel editorPanel = new JPanel();
        private final JPanel editorWrap = new JPanel(new BorderLayout());
        private final JComboBox<String> themeBox = new JComboBox<>(new String[]{"Light", "Dark", "System"});
        private final JLabel hintLabel = new JLabel("");


        private byte[] currentMessage = new byte[0];
        private byte[] originalMessage = null;
        private StreamLocation location = null;
        private List<Object> currentRoots;
        private String parseError;
        private boolean modified = false;
        private final List<PathEdit> edits = new ArrayList<>();
        protected HttpRequestResponse lastResp;

        ObjectModifyTab(JavaObjectModifyExtension owner) {
            this.owner = owner;
            buildUi();
        }

        private void buildUi() {
            root.setLayout(new BorderLayout(0, 0));

            // Tree
            tree.setRootVisible(false);
            tree.setShowsRootHandles(true);
            tree.setRowHeight(24);
            tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
            tree.getSelectionModel().addTreeSelectionListener(e -> showEditor());
            tree.setCellRenderer(new ValueTreeRenderer());

            JScrollPane treeScroll = new JScrollPane(tree);
            treeScroll.setMinimumSize(new Dimension(300, 80));

            // Editor panel (rendered into the split pane)
            editorPanel.setLayout(new BorderLayout());
            editorPanel.setBorder(new EmptyBorder(10, 14, 10, 14));
            editorWrap.setOpaque(false);
            hintLabel.setFont(hintLabel.getFont().deriveFont(Font.PLAIN, 11f));

            JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScroll, editorWrap);
            split.setResizeWeight(0.45);
            split.setBorder(null);
            split.setDividerSize(4);
            split.setContinuousLayout(true);

            // Toolbar
            JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 8));
            toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, java.awt.Color.GRAY));

            JLabel indexLabel = new JLabel("Object index");
            indexLabel.setFont(indexLabel.getFont().deriveFont(Font.BOLD, 12f));
            indexField.setColumns(4);
            indexField.setToolTipText("Index of the top-level serialized object to display (0-based).");
            indexField.addActionListener(e -> rerender());

            autoApply.setOpaque(false);
            autoApply.setFont(autoApply.getFont().deriveFont(Font.PLAIN, 12f));
            autoApply.addActionListener(e -> updateApplyState());

            apply.setFocusPainted(false);
            apply.setFont(apply.getFont().deriveFont(Font.BOLD, 12f));
            apply.setEnabled(false);
            apply.addActionListener(e -> applyEdits(true));

            // Theme selector
            String cur = "System";
            if ("light".equals(themeMode)) cur = "Light";
            else if ("dark".equals(themeMode)) cur = "Dark";
            themeBox.setSelectedItem(cur);
            themeBox.setToolTipText("Switch the editor's light/dark theme");
            themeBox.addActionListener(e -> {
                String sel = (String) themeBox.getSelectedItem();
                themeMode = sel == null ? "system" : sel.toLowerCase();
                palette = ThemePalette.forMode(themeMode);
                if (owner != null && owner.api != null) {
                    owner.api.persistence().preferences().setString("java_object_modify.theme", themeMode);
                }
                applyTheme();
            });

            JLabel themeLabel = new JLabel("Theme");
            themeLabel.setFont(themeLabel.getFont().deriveFont(Font.PLAIN, 12f));

            toolbar.add(indexLabel);
            toolbar.add(indexField);
            toolbar.add(Box.createHorizontalStrut(6));
            toolbar.add(autoApply);
            toolbar.add(Box.createHorizontalStrut(6));
            toolbar.add(apply);
            toolbar.add(Box.createHorizontalGlue());
            toolbar.add(themeLabel);
            toolbar.add(themeBox);

            // Status bar
            JPanel bottom = new JPanel(new BorderLayout());
            bottom.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, java.awt.Color.GRAY));
            source.setFont(source.getFont().deriveFont(Font.BOLD, 11f));
            source.setBorder(new EmptyBorder(0, 12, 0, 0));
            status.setFont(status.getFont().deriveFont(Font.PLAIN, 11f));
            status.setBorder(new EmptyBorder(0, 10, 0, 12));
            bottom.add(source, BorderLayout.WEST);
            bottom.add(status, BorderLayout.EAST);

            root.add(toolbar, BorderLayout.NORTH);
            root.add(split, BorderLayout.CENTER);
            root.add(bottom, BorderLayout.SOUTH);
            applyTheme();
        }

        /** Repaint the whole tab with the current palette. */
        private void applyTheme() {
            ThemePalette p = palette;
            root.setBackground(p.panelBg);
            tree.setBackground(p.inputBg);
            tree.setForeground(p.text);
            tree.setFont(tree.getFont().deriveFont(Font.PLAIN, 13f));
            tree.setBorder(new EmptyBorder(6, 6, 6, 6));
            editorPanel.setBackground(p.panelBg);
            hintLabel.setForeground(p.textMuted);
            status.setForeground(p.textMuted);
            source.setForeground(p.accentDark);
            for (Component c : root.getComponents()) if (c instanceof JPanel) c.setBackground(p.panelBg);
            root.revalidate();
            root.repaint();
            // Re-render current editor view
            SwingUtilities.invokeLater(this::showEditor);
        }

        // ---- ExtensionProvidedEditor (shared) ----

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            lastResp = requestResponse;
            byte[] raw = pickMessage(requestResponse);
            currentMessage = raw == null ? new byte[0] : raw;
            originalMessage = currentMessage.clone();
            parseError = null;
            parse();
            rerender();
            modified = false;
            edits.clear();
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            byte[] raw = pickMessage(requestResponse);
            return raw != null && locate(raw) != null;
        }

        @Override
        public String caption() {
            return TAB_NAME;
        }

        @Override
        public Component uiComponent() {
            return root;
        }

        @Override
        public burp.api.montoya.http.message.responses.HttpResponse getResponse() {
            return lastResp == null ? null : lastResp.response();
        }

        // ---- HttpRequestEditor passthroughs ----

        @Override
        public burp.api.montoya.http.message.requests.HttpRequest getRequest() {
            return lastResp == null ? null : lastResp.request();
        }

        @Override
        public burp.api.montoya.ui.Selection selectedData() {
            return null;
        }

        @Override
        public boolean isModified() {
            return modified;
        }

        // ---- helpers ----

        private byte[] pickMessage(HttpRequestResponse rr) {
            if (rr == null) return null;
            if (rr.request() != null) return rr.request().toByteArray().getBytes();
            if (rr.response() != null) return rr.response().toByteArray().getBytes();
            return null;
        }

        private static int scanForMagic(byte[] data) {
            if (data == null) return -1;
            for (int i = 0; i + 1 < data.length; i++) {
                if ((data[i] & 0xFF) == 0xAC && (data[i + 1] & 0xFF) == 0xED) return i;
            }
            return -1;
        }

        /** Locate the serialized stream: raw AC ED bytes, or a base64 token. */
        static StreamLocation locate(byte[] raw) {
            if (raw == null || raw.length == 0) return null;
            int off = scanForMagic(raw);
            if (off >= 0) return new StreamLocation(raw, off, off, false, null);
            // base64: find runs of base64 chars, decode, check AC ED magic
            int n = raw.length;
            int start = -1;
            for (int i = 0; i < n; i++) {
                int c = raw[i] & 0xFF;
                boolean isB64 = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                        || (c >= '0' && c <= '9') || c == '+' || c == '/';
                if (isB64) {
                    if (start < 0) start = i;
                } else {
                    if (start >= 0) {
                        StreamLocation l = tryB64(raw, start, i);
                        if (l != null) return l;
                        start = -1;
                    }
                }
            }
            if (start >= 0) return tryB64(raw, start, n);
            return null;
        }

        private static StreamLocation tryB64(byte[] raw, int start, int end) {
            // Include any trailing '=' padding in the token bounds so the
            // splice replaces the entire token (padding and all).
            int pad = 0;
            while (end + pad < raw.length && raw[end + pad] == (byte) '=') pad++;
            String token = new String(raw, start, end - start + pad, java.nio.charset.StandardCharsets.US_ASCII);
            if (token.length() < 8) return null;
            byte[] dec = null;
            for (int attempt = 0; attempt <= 2; attempt++) {
                String candidate = attempt == 0 ? token : token + "=".repeat(attempt);
                try {
                    dec = java.util.Base64.getDecoder().decode(candidate);
                    break;
                } catch (IllegalArgumentException ignored) {
                    // padding mismatch; try harder
                }
            }
            if (dec == null) return null;
            if (dec.length < 2 || (dec[0] & 0xFF) != 0xAC || (dec[1] & 0xFF) != 0xED) return null;
            // Compute the exact byte range to replace: start..(end+pad)
            int realEnd = start + token.length();
            return new StreamLocation(raw, start, realEnd, true, token);
        }

        private void parse() {
            if (currentMessage == null || currentMessage.length == 0) {
                currentRoots = null;
                location = null;
                parseError = "Empty message";
                return;
            }
            location = locate(currentMessage);
            if (location == null) {
                currentRoots = null;
                parseError = "No Java serialization stream (raw AC ED or base64 token) found";
                return;
            }
            byte[] stream = location.base64 ? location.decoded
                    : java.util.Arrays.copyOfRange(currentMessage, location.start, location.end == location.start ? currentMessage.length : location.end);
            if (location.base64) {
                // decoded already contains exactly the stream
            } else {
                stream = java.util.Arrays.copyOfRange(currentMessage, location.start, currentMessage.length);
            }
            JavaSerializationProtocol.ParseResult pr = JavaSerializationProtocol.parse(stream);
            if (!pr.ok()) {
                currentRoots = null;
                parseError = pr.error;
                return;
            }
            currentRoots = pr.topLevels;
            parseError = null;
        }

        private void rerender() {
            treeRoot.removeAllChildren();
            if (currentRoots == null || currentRoots.isEmpty()) {
                treeRoot.add(new DefaultMutableTreeNode("(no parseable objects)"));
            } else {
                int idx = clampIndex();
                List<Object> subset = List.of(currentRoots.get(idx));
                addEntries(treeRoot, JavaSerializationProtocol.toValueEntries(subset));
                if (currentRoots.size() > 1) {
                    treeRoot.add(new DefaultMutableTreeNode("… " + (currentRoots.size() - (idx + 1)) + " further top-level object(s)"));
                }
            }
            treeModel.reload();
            expandAll();
            refreshStatus();
        }

        private void addEntries(DefaultMutableTreeNode parent, List<ValueEntry> entries) {
            Map<String, DefaultMutableTreeNode> map = new HashMap<>();
            for (ValueEntry ve : entries) map.put(ve.path, new DefaultMutableTreeNode(ve));
            for (ValueEntry ve : entries) {
                DefaultMutableTreeNode n = map.get(ve.path);
                DefaultMutableTreeNode p = parentOf(ve.path, map, parent);
                if (p != null) p.add(n);
            }
        }

        private DefaultMutableTreeNode parentOf(String path, Map<String, DefaultMutableTreeNode> map,
                                                DefaultMutableTreeNode root) {
            if (path == null || path.equals("/")) return root;
            int i = path.lastIndexOf('/');
            while (i > 0) {
                String pp = path.substring(0, i);
                DefaultMutableTreeNode node = map.get(pp);
                if (node != null) return node;
                i = pp.lastIndexOf('/');
            }
            return root;
        }

        private int clampIndex() {
            try {
                int v = Integer.parseInt(indexField.getText().trim());
                if (v < 0) return 0;
                if (v >= currentRoots.size()) return currentRoots.size() - 1;
                return v;
            } catch (NumberFormatException nfe) {
                return 0;
            }
        }

        private void expandAll() {
            for (int i = 0; i < tree.getRowCount(); i++) tree.expandRow(i);
        }

        private void refreshStatus() {
            if (parseError != null) {
                status.setForeground(palette.danger);
                status.setText("⚠ " + parseError);
            } else if (currentRoots != null && location != null) {
                status.setForeground(JavaObjectModifyExtension.palette.textMuted);
                status.setText(currentRoots.size() + " object" + (currentRoots.size() == 1 ? "" : "s")
                        + "  •  offset " + location.start
                        + (location.base64 ? "  •  base64" : "") + "  •  " + currentMessage.length + " bytes");
            } else {
                status.setForeground(palette.warn);
                status.setText("No serialized data");
            }
            source.setText((lastResp == null || lastResp.request() == null) ? "◈ RESPONSE" : "◈ REQUEST");
            if (currentRoots != null && location != null) {
                hintLabel.setText(location.base64
                        ? "Editing a base64-encoded stream — changes are re-encoded and stay base64."
                        : "Editing a raw AC ED stream — changes are spliced in place.");
            }
        }

        private void showEditor() {
            editorPanel.removeAll();
            Object uo = tree.getLastSelectedPathComponent() == null ? null
                    : ((DefaultMutableTreeNode) tree.getLastSelectedPathComponent()).getUserObject();

            JPanel center;
            if (!(uo instanceof ValueEntry)) {
                center = placeholder("Select a value in the tree to edit it",
                        "Objects, arrays and class nodes are containers; click any scalar value.");
            } else {
                ValueEntry ve = (ValueEntry) uo;
                if (!ve.editable) {
                    center = placeholder("Container node",
                            ve.label + " — expand it and pick a scalar value.");
                } else {
                    center = buildForm(ve);
                }
            }
            editorPanel.add(center, BorderLayout.CENTER);
            editorPanel.add(hintLabel, BorderLayout.SOUTH);
            editorWrap.removeAll();
            editorWrap.add(editorPanel, BorderLayout.CENTER);
            editorWrap.revalidate();
            editorWrap.repaint();
        }

        private JPanel placeholder(String title, String sub) {
            JPanel p = new JPanel(new GridBagLayout());
            p.setOpaque(false);
            GridBagConstraints g = new GridBagConstraints();
            g.insets = new Insets(4, 4, 4, 4);
            g.gridwidth = GridBagConstraints.REMAINDER;
            g.anchor = GridBagConstraints.CENTER;
            JLabel t = new JLabel(title);
            t.setFont(t.getFont().deriveFont(Font.BOLD, 15f));
            t.setForeground(JavaObjectModifyExtension.palette.textMuted);
            g.gridy = 0;
            p.add(t, g);
            JLabel s = new JLabel(sub);
            s.setFont(s.getFont().deriveFont(Font.PLAIN, 12f));
            s.setForeground(JavaObjectModifyExtension.palette.textMuted);
            g.gridy = 1;
            p.add(s, g);
            return p;
        }



        private JPanel buildForm(ValueEntry ve) {
            JPanel form = new JPanel(new GridBagLayout());
            form.setOpaque(false);
            form.setBackground(palette.surfaceBg);
            form.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(palette.border, 1, true),
                    new EmptyBorder(18, 18, 18, 18)));
            GridBagConstraints g = new GridBagConstraints();
            g.insets = new Insets(6, 8, 6, 8);
            g.anchor = GridBagConstraints.LINE_START;
            g.fill = GridBagConstraints.HORIZONTAL;

            g.gridx = 0; g.gridy = 0;
            form.add(keyLabel("PATH"), g);
            g.gridx = 1; g.weightx = 1;
            JLabel pathV = new JLabel(ve.path);
            pathV.setFont(pathV.getFont().deriveFont(Font.BOLD, 12f));
            pathV.setForeground(JavaObjectModifyExtension.palette.text);
            form.add(pathV, g);
            g.weightx = 0;

            g.gridx = 0; g.gridy = 1;
            form.add(keyLabel("TYPE"), g);
            g.gridx = 1;
            JLabel typeV = new JLabel(ve.label);
            typeV.setFont(typeV.getFont().deriveFont(Font.PLAIN, 12f));
            typeV.setForeground(typeColor(ve));
            form.add(typeV, g);

            g.gridx = 0; g.gridy = 2;
            form.add(keyLabel("VALUE"), g);
            g.gridx = 1;
            JTextField field = new JTextField(28);
            field.setText(textValue(ve));
            field.setFont(field.getFont().deriveFont(Font.PLAIN, 13f));
            field.setBackground(JavaObjectModifyExtension.palette.inputBg);
            field.setForeground(JavaObjectModifyExtension.palette.text);
            field.setCaretColor(JavaObjectModifyExtension.palette.text);
            field.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(palette.inputBorder),
                    new EmptyBorder(6, 8, 6, 8)));
            field.getDocument().addDocumentListener(new DocumentListener() {
                public void insertUpdate(DocumentEvent e) { onEdit(); }
                public void removeUpdate(DocumentEvent e) { onEdit(); }
                public void changedUpdate(DocumentEvent e) { onEdit(); }
                void onEdit() {
                    recordEdit(ve.path, field.getText());
                    if (autoApply.isSelected()) applyEdits(false);
                }
            });
            form.add(field, g);

            g.gridx = 0; g.gridy = 3;
            form.add(keyLabel("NOTE"), g);
            g.gridx = 1;
            JLabel note = new JLabel("Changes apply to the live message on each keystroke when auto-apply is on.");
            note.setFont(note.getFont().deriveFont(Font.PLAIN, 11f));
            note.setForeground(JavaObjectModifyExtension.palette.textMuted);
            form.add(note, g);

            return form;
        }

        private JLabel keyLabel(String text) {
            JLabel l = new JLabel(text);
            l.setFont(l.getFont().deriveFont(Font.BOLD, 11f));
            l.setForeground(JavaObjectModifyExtension.palette.accentDark);
            return l;
        }

        static Color typeColor(ValueEntry ve) {
            Object n = ve.node;
            if (n instanceof SString) return JavaObjectModifyExtension.palette.stringC;
            if (n instanceof Number) return JavaObjectModifyExtension.palette.numC;
            if (n instanceof Boolean) return JavaObjectModifyExtension.palette.boolC;
            if (n instanceof Character) return JavaObjectModifyExtension.palette.stringC;
            return JavaObjectModifyExtension.palette.textMuted;
        }

        private String textValue(ValueEntry ve) {
            Object node = ve.node;
            if (node instanceof SString) return ((SString) node).value;
            if (node instanceof Number || node instanceof Character || node instanceof Boolean)
                return node.toString();
            return "";
        }

        private void recordEdit(String path, String text) {
            for (int i = 0; i < edits.size(); i++) {
                if (edits.get(i).path.equals(path)) {
                    edits.set(i, new PathEdit(path, text));
                    updateApplyState();
                    return;
                }
            }
            edits.add(new PathEdit(path, text));
            updateApplyState();
        }

        /** Apply button is clickable when there are pending edits and auto-apply is off. */
        private void updateApplyState() {
            apply.setEnabled(currentRoots != null && !autoApply.isSelected() && !edits.isEmpty());
        }

        private void applyEdits(boolean manual) {
            if (currentRoots == null) return;
            for (PathEdit pe : edits) {
                Object target = JavaSerializationProtocol.findNode(currentRoots, pe.path);
                JavaSerializationProtocol.setValueAt(currentRoots, pe.path,
                        parseEdited(target, pe.text));
            }
            JavaSerializationProtocol.EncodeResult er = JavaSerializationProtocol.encode(currentRoots);
            if (!er.ok()) {
                status.setText("Re-serialize failed: " + er.error);
                return;
            }
            byte[] newSerialized = er.bytes;
            byte[] base = originalMessage == null ? currentMessage : originalMessage;
            byte[] newRaw;
            if (location != null) {
                byte[] replacement = location.base64
                        ? java.util.Base64.getEncoder().encodeToString(newSerialized).getBytes(java.nio.charset.StandardCharsets.US_ASCII)
                        : newSerialized;
                int prefixLen = location.start;
                int suffixLen = base.length - location.end;
                newRaw = new byte[prefixLen + replacement.length + suffixLen];
                System.arraycopy(base, 0, newRaw, 0, prefixLen);
                System.arraycopy(replacement, 0, newRaw, prefixLen, replacement.length);
                System.arraycopy(base, location.end, newRaw, prefixLen + replacement.length, suffixLen);
            } else {
                newRaw = newSerialized;
            }
            modified = true;
            if (lastResp != null) {
                if (lastResp.request() != null) {
                    lastResp = HttpRequestResponse.httpRequestResponse(
                            HttpRequest.httpRequest(ByteArray.byteArray(newRaw)),
                            lastResp.response());
                } else if (lastResp.response() != null) {
                    lastResp = HttpRequestResponse.httpRequestResponse(
                            lastResp.request(),
                            HttpResponse.httpResponse(ByteArray.byteArray(newRaw)));
                }
            }
            currentMessage = newRaw;
            location = locate(base);
            if (manual) {
                status.setText("Applied " + edits.size() + " edit(s), " + newSerialized.length + " serialized bytes");
            }
            updateApplyState();
            // Burp reads the modified message from getRequest()/isModified().
        }

        private Object parseEdited(Object target, String text) {
            if (target instanceof SString) return new SString(text);
            if (target instanceof Boolean) return Boolean.parseBoolean(text.trim());
            if (target instanceof Byte) return Byte.parseByte(text.trim());
            if (target instanceof Short) return Short.parseShort(text.trim());
            if (target instanceof Integer) return Integer.decode(text.trim());
            if (target instanceof Long) return Long.decode(text.trim());
            if (target instanceof Float) return Float.parseFloat(text.trim());
            if (target instanceof Double) return Double.parseDouble(text.trim());
            if (target instanceof Character) {
                String t = text.trim();
                return t.length() == 1 ? t.charAt(0) : '\0';
            }
            return text;
        }
    }

    /** Request editor provider returns editable request tabs. */
    private static class JavaObjectModifyHttpEditor extends ObjectModifyTab {
        JavaObjectModifyHttpEditor(JavaObjectModifyExtension owner) {
            super(owner);
        }

        @Override
        public burp.api.montoya.http.message.requests.HttpRequest getRequest() {
            return super.getRequest();
        }
    }

    /** Response editor provider returns response tabs. */
    private static class JavaObjectModifyHttpResponseEditor extends ObjectModifyTab {
        JavaObjectModifyHttpResponseEditor(JavaObjectModifyExtension owner) {
            super(owner);
        }

        @Override
        public burp.api.montoya.http.message.responses.HttpResponse getResponse() {
            return lastResp == null ? null : lastResp.response();
        }
    }

    // ------------------------------------------------------------------
    // Data holders
    // ------------------------------------------------------------------

    /** Where the serialized stream lives in the raw message. */
    static final class StreamLocation {
        final int start;        // byte offset of the token/raw stream
        final int end;          // byte offset (exclusive)
        final boolean base64;
        final String token;     // the base64 text if base64
        final byte[] decoded;   // decode Runnable convenience

        StreamLocation(byte[] raw, int start, int end, boolean base64, String token) {
            this.start = start;
            this.end = end;
            this.base64 = base64;
            this.token = token;
            this.decoded = base64 ? java.util.Base64.getDecoder().decode(token) : null;
        }

        byte[] bytes() {
            return base64 ? decoded : null;
        }
    }

    /** Tree renderer with type coloring and bullet icons (theme-aware). */
    static final class ValueTreeRenderer extends DefaultTreeCellRenderer {
        @Override
        public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded,
                                                      boolean leaf, int row, boolean hasFocus) {
            super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
            setBackgroundNonSelectionColor(JavaObjectModifyExtension.palette.inputBg);
            setBackgroundSelectionColor(JavaObjectModifyExtension.palette.accent);
            setTextNonSelectionColor(JavaObjectModifyExtension.palette.text);
            setTextSelectionColor(Color.WHITE);
            if (!(value instanceof DefaultMutableTreeNode)) return this;
            Object uo = ((DefaultMutableTreeNode) value).getUserObject();
            if (!(uo instanceof ValueEntry)) {
                setIcon(new BulletIcon(JavaObjectModifyExtension.palette.refC));
                return this;
            }
            ValueEntry ve = (ValueEntry) uo;
            setText(ve.label);
            setFont(getFont().deriveFont(ve.editable ? Font.PLAIN : Font.BOLD,
                    ve.editable ? 13f : 12f));
            if (!sel) {
                setForeground(ObjectModifyTab.typeColor(ve));
            }
            setIcon(iconFor(ve));
            return this;
        }

        private Icon iconFor(ValueEntry ve) {
            Object n = ve.node;
            if (n == null || n == SNull.INSTANCE) return new BulletIcon(JavaObjectModifyExtension.palette.nullC);
            if (n instanceof SString) return new BulletIcon(JavaObjectModifyExtension.palette.stringC);
            if (n instanceof Boolean) return new BulletIcon(JavaObjectModifyExtension.palette.boolC);
            if (n instanceof Number) return new BulletIcon(JavaObjectModifyExtension.palette.numC);
            if (n instanceof SNode) return new BulletIcon(JavaObjectModifyExtension.palette.accent);
            return new BulletIcon(JavaObjectModifyExtension.palette.accent);
        }
    }

    /** A small colored dot used as a tree icon. */
    static final class BulletIcon implements Icon {
        private final Color color;

        BulletIcon(Color color) {
            this.color = color;
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(color);
                g2.fillOval(x + 2, y + 3, 10, 10);
            } finally {
                g2.dispose();
            }
        }

        @Override
        public int getIconWidth() {
            return 14;
        }

        @Override
        public int getIconHeight() {
            return 16;
        }
    }

    static final class PathEdit {
        final String path;
        final String text;
        PathEdit(String path, String text) { this.path = path; this.text = text; }
    }
}
