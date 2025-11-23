package scanner;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Objects;

public class SecurityIssue {
    public enum Severity {
        HIGH("High", "#FF4444"),
        MEDIUM("Medium", "#FFA500"),
        LOW("Low", "#FFD700"),
        INFO("Info", "#4169E1");

        private final String label;
        private final String color;

        Severity(String label, String color) {
            this.label = label;
            this.color = color;
        }

        public String getLabel() {
            return label;
        }

        public String getColor() {
            return color;
        }
    }

    private final String url;
    private final String title;
    private final String description;
    private final Severity severity;
    private final String evidence;
    private final LocalDateTime foundAt;
    private final String category;

    public SecurityIssue(String url, String title, String description, Severity severity, String evidence, String category) {
        this.url = url;
        this.title = title;
        this.description = description;
        this.severity = severity;
        this.evidence = evidence;
        this.foundAt = LocalDateTime.now();
        this.category = category;
    }

    public String getUrl() {
        return url;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getEvidence() {
        return evidence;
    }

    public LocalDateTime getFoundAt() {
        return foundAt;
    }

    public String getCategory() {
        return category;
    }

    public String getFormattedTime() {
        return foundAt.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecurityIssue that = (SecurityIssue) o;
        return Objects.equals(url, that.url) &&
               Objects.equals(title, that.title) &&
               Objects.equals(category, that.category);
    }

    @Override
    public int hashCode() {
        return Objects.hash(url, title, category);
    }

    @Override
    public String toString() {
        return String.format("[%s] %s - %s", severity.getLabel(), title, url);
    }
}
