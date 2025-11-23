package ui;

import scanner.IssueManager;
import scanner.SecurityIssue;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.Comparator;
import java.util.List;

public class SecurityScannerPanel extends JPanel {
    private final IssueManager issueManager;
    private final DefaultTableModel tableModel;
    private final JTable issueTable;
    private final JLabel statsLabel;
    private final JTextArea detailsArea;
    private final TableRowSorter<DefaultTableModel> sorter;

    public SecurityScannerPanel(IssueManager issueManager) {
        this.issueManager = issueManager;
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Header panel with stats and controls
        JPanel headerPanel = createHeaderPanel();
        add(headerPanel, BorderLayout.NORTH);

        // Split pane for table and details
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.6);

        // Table panel
        String[] columns = {"Severity", "Category", "Title", "URL", "Time"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        issueTable = new JTable(tableModel);
        issueTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        issueTable.setRowHeight(25);
        issueTable.getTableHeader().setReorderingAllowed(false);

        // Set up table sorting
        sorter = new TableRowSorter<>(tableModel);
        issueTable.setRowSorter(sorter);

        // Custom comparator for severity column
        sorter.setComparator(0, new Comparator<String>() {
            @Override
            public int compare(String s1, String s2) {
                return getSeverityOrder(s1) - getSeverityOrder(s2);
            }

            private int getSeverityOrder(String severity) {
                return switch (severity) {
                    case "High" -> 0;
                    case "Medium" -> 1;
                    case "Low" -> 2;
                    case "Info" -> 3;
                    default -> 4;
                };
            }
        });

        // Set column widths
        issueTable.getColumnModel().getColumn(0).setPreferredWidth(80);
        issueTable.getColumnModel().getColumn(0).setMaxWidth(100);
        issueTable.getColumnModel().getColumn(1).setPreferredWidth(100);
        issueTable.getColumnModel().getColumn(1).setMaxWidth(150);
        issueTable.getColumnModel().getColumn(2).setPreferredWidth(300);
        issueTable.getColumnModel().getColumn(3).setPreferredWidth(400);
        issueTable.getColumnModel().getColumn(4).setPreferredWidth(140);
        issueTable.getColumnModel().getColumn(4).setMaxWidth(180);

        // Custom renderer for severity column
        issueTable.getColumnModel().getColumn(0).setCellRenderer(new SeverityCellRenderer());

        // Selection listener for showing details
        issueTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelectedIssueDetails();
            }
        });

        JScrollPane tableScrollPane = new JScrollPane(issueTable);
        splitPane.setTopComponent(tableScrollPane);

        // Details panel
        detailsArea = new JTextArea();
        detailsArea.setEditable(false);
        detailsArea.setLineWrap(true);
        detailsArea.setWrapStyleWord(true);
        detailsArea.setMargin(new Insets(10, 10, 10, 10));
        detailsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane detailsScrollPane = new JScrollPane(detailsArea);
        detailsScrollPane.setBorder(BorderFactory.createTitledBorder("Issue Details"));
        splitPane.setBottomComponent(detailsScrollPane);

        add(splitPane, BorderLayout.CENTER);

        // Stats label
        statsLabel = new JLabel("No issues found");
        statsLabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
        add(statsLabel, BorderLayout.SOUTH);

        // Register listener for new issues
        issueManager.addListener(this::addIssueToTable);

        // Initial load
        loadIssues();
    }

    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        JLabel titleLabel = new JLabel("Security Issues Scanner");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 16));
        panel.add(titleLabel, BorderLayout.WEST);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));

        JButton refreshButton = new JButton("Refresh");
        refreshButton.addActionListener(e -> loadIssues());
        buttonPanel.add(refreshButton);

        JButton clearButton = new JButton("Clear All");
        clearButton.addActionListener(e -> clearIssues());
        buttonPanel.add(clearButton);

        JComboBox<String> filterCombo = new JComboBox<>(new String[]{
            "All Issues", "High Severity", "Medium Severity", "Low Severity", "Info"
        });
        filterCombo.addActionListener(e -> filterIssues((String) filterCombo.getSelectedItem()));
        buttonPanel.add(new JLabel("Filter:"));
        buttonPanel.add(filterCombo);

        panel.add(buttonPanel, BorderLayout.EAST);

        return panel;
    }

    private void addIssueToTable(SecurityIssue issue) {
        SwingUtilities.invokeLater(() -> {
            tableModel.addRow(new Object[]{
                issue.getSeverity().getLabel(),
                issue.getCategory(),
                issue.getTitle(),
                issue.getUrl(),
                issue.getFormattedTime()
            });
            updateStats();
        });
    }

    private void loadIssues() {
        tableModel.setRowCount(0);
        List<SecurityIssue> issues = issueManager.getAllIssues();
        for (SecurityIssue issue : issues) {
            tableModel.addRow(new Object[]{
                issue.getSeverity().getLabel(),
                issue.getCategory(),
                issue.getTitle(),
                issue.getUrl(),
                issue.getFormattedTime()
            });
        }
        updateStats();
    }

    private void clearIssues() {
        int result = JOptionPane.showConfirmDialog(
            this,
            "Are you sure you want to clear all issues?",
            "Clear Issues",
            JOptionPane.YES_NO_OPTION
        );
        if (result == JOptionPane.YES_OPTION) {
            issueManager.clear();
            tableModel.setRowCount(0);
            detailsArea.setText("");
            updateStats();
        }
    }

    private void filterIssues(String filter) {
        if ("All Issues".equals(filter)) {
            sorter.setRowFilter(null);
        } else {
            String severity = filter.replace(" Severity", "");
            sorter.setRowFilter(RowFilter.regexFilter(severity, 0));
        }
        updateStats();
    }

    private void showSelectedIssueDetails() {
        int selectedRow = issueTable.getSelectedRow();
        if (selectedRow >= 0) {
            int modelRow = issueTable.convertRowIndexToModel(selectedRow);
            String url = (String) tableModel.getValueAt(modelRow, 3);
            String title = (String) tableModel.getValueAt(modelRow, 2);
            String category = (String) tableModel.getValueAt(modelRow, 1);

            // Find the issue in the manager
            List<SecurityIssue> issues = issueManager.getAllIssues();
            for (SecurityIssue issue : issues) {
                if (issue.getUrl().equals(url) &&
                    issue.getTitle().equals(title) &&
                    issue.getCategory().equals(category)) {
                    displayIssueDetails(issue);
                    break;
                }
            }
        }
    }

    private void displayIssueDetails(SecurityIssue issue) {
        StringBuilder details = new StringBuilder();
        details.append("SEVERITY: ").append(issue.getSeverity().getLabel()).append("\n");
        details.append("CATEGORY: ").append(issue.getCategory()).append("\n");
        details.append("TITLE: ").append(issue.getTitle()).append("\n\n");
        details.append("URL: ").append(issue.getUrl()).append("\n\n");
        details.append("DESCRIPTION:\n").append(issue.getDescription()).append("\n\n");
        details.append("EVIDENCE:\n").append(issue.getEvidence()).append("\n\n");
        details.append("FOUND AT: ").append(issue.getFormattedTime()).append("\n");

        detailsArea.setText(details.toString());
        detailsArea.setCaretPosition(0);
    }

    private void updateStats() {
        int total = issueTable.getRowCount();
        int high = 0, medium = 0, low = 0, info = 0;

        for (int i = 0; i < tableModel.getRowCount(); i++) {
            String severity = (String) tableModel.getValueAt(i, 0);
            switch (severity) {
                case "High" -> high++;
                case "Medium" -> medium++;
                case "Low" -> low++;
                case "Info" -> info++;
            }
        }

        String stats = String.format(
            "Total Issues: %d | High: %d | Medium: %d | Low: %d | Info: %d (Showing: %d)",
            issueManager.getIssueCount(), high, medium, low, info, total
        );
        statsLabel.setText(stats);
    }

    private static class SeverityCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                      boolean isSelected, boolean hasFocus,
                                                      int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (!isSelected) {
                String severity = (String) value;
                switch (severity) {
                    case "High" -> c.setBackground(new Color(255, 200, 200));
                    case "Medium" -> c.setBackground(new Color(255, 230, 200));
                    case "Low" -> c.setBackground(new Color(255, 255, 200));
                    case "Info" -> c.setBackground(new Color(200, 220, 255));
                    default -> c.setBackground(Color.WHITE);
                }
            }

            setHorizontalAlignment(CENTER);
            setFont(getFont().deriveFont(Font.BOLD));

            return c;
        }
    }
}
