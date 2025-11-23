package scanner;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

public class IssueManager {
    private final Set<SecurityIssue> issues = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final List<Consumer<SecurityIssue>> listeners = new ArrayList<>();

    public boolean addIssue(SecurityIssue issue) {
        boolean added = issues.add(issue);
        if (added) {
            notifyListeners(issue);
        }
        return added;
    }

    public void addListener(Consumer<SecurityIssue> listener) {
        listeners.add(listener);
    }

    private void notifyListeners(SecurityIssue issue) {
        for (Consumer<SecurityIssue> listener : listeners) {
            listener.accept(issue);
        }
    }

    public List<SecurityIssue> getAllIssues() {
        return new ArrayList<>(issues);
    }

    public List<SecurityIssue> getIssuesBySeverity(SecurityIssue.Severity severity) {
        return issues.stream()
                .filter(issue -> issue.getSeverity() == severity)
                .toList();
    }

    public Map<String, Long> getIssueCountByCategory() {
        Map<String, Long> counts = new HashMap<>();
        for (SecurityIssue issue : issues) {
            counts.merge(issue.getCategory(), 1L, Long::sum);
        }
        return counts;
    }

    public void clear() {
        issues.clear();
    }

    public int getIssueCount() {
        return issues.size();
    }
}
