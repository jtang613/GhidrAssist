package ghidrassist.agent.react;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Manages a dynamic todo list for tracking investigation progress.
 * Todos evolve as the agent learns more about the problem.
 */
public class TodoListManager {

    public enum TodoStatus {
        PENDING,
        IN_PROGRESS,
        COMPLETE
    }

    public static class Todo {
        private String task;
        private TodoStatus status;
        private String evidence;  // What we learned when completing this
        private int priority;     // Higher = more important

        public Todo(String task, int priority) {
            this.task = task;
            this.status = TodoStatus.PENDING;
            this.priority = priority;
        }

        public String getTask() { return task; }
        public TodoStatus getStatus() { return status; }
        public String getEvidence() { return evidence; }
        public int getPriority() { return priority; }

        public void setStatus(TodoStatus status) { this.status = status; }
        public void setEvidence(String evidence) { this.evidence = evidence; }
        public void setPriority(int priority) { this.priority = priority; }
    }

    private final List<Todo> todos;
    private final String objective;

    public TodoListManager(String objective) {
        this.objective = objective;
        this.todos = new ArrayList<>();
    }

    /**
     * Initialize todo list from LLM response.
     * Parses a markdown checklist or numbered list.
     */
    public void initializeFromLLMResponse(String llmResponse) {
        // Clear any existing todos
        todos.clear();

        if (llmResponse == null || llmResponse.trim().isEmpty()) {
            // Fallback: add generic investigation step
            todos.add(new Todo("Investigate the query using available tools", 10));
            return;
        }

        // Parse the LLM response for todo items
        // Expected format: markdown checklist or numbered list
        String[] lines = llmResponse.split("\n");
        int priority = 10;

        for (String line : lines) {
            line = line.trim();

            // Skip empty lines and headers
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            // Parse markdown checkbox format: - [ ] Task or - [x] Task
            if (line.matches("^-\\s*\\[[ xX]\\]\\s+.+")) {
                String task = line.replaceFirst("^-\\s*\\[[ xX]\\]\\s+", "").trim();
                if (!task.isEmpty()) {
                    todos.add(new Todo(task, priority));
                    priority = Math.max(1, priority - 1);
                }
            }
            // Parse numbered list format: 1. Task
            else if (line.matches("^\\d+\\.\\s+.+")) {
                String task = line.replaceFirst("^\\d+\\.\\s+", "").trim();
                if (!task.isEmpty()) {
                    todos.add(new Todo(task, priority));
                    priority = Math.max(1, priority - 1);
                }
            }
            // Parse bullet list format: - Task or * Task
            else if (line.matches("^[\\-\\*]\\s+.+")) {
                String task = line.replaceFirst("^[\\-\\*]\\s+", "").trim();
                if (!task.isEmpty()) {
                    todos.add(new Todo(task, priority));
                    priority = Math.max(1, priority - 1);
                }
            }
        }

        // If we didn't find any todos, add a fallback
        if (todos.isEmpty()) {
            todos.add(new Todo("Investigate the query using available tools", 10));
        }
    }

    /**
     * Add a new todo dynamically based on discoveries.
     */
    public void addTodo(String task, int priority) {
        todos.add(new Todo(task, priority));
    }

    /**
     * Mark a todo as complete with evidence.
     */
    public void completeTodo(String task, String evidence) {
        for (Todo todo : todos) {
            if (todo.getTask().equals(task) || todo.getTask().contains(task)) {
                todo.setStatus(TodoStatus.COMPLETE);
                todo.setEvidence(evidence);
                break;
            }
        }
    }

    /**
     * Mark a todo as in progress.
     */
    public void setInProgress(String task) {
        for (Todo todo : todos) {
            if (todo.getTask().equals(task) || todo.getTask().contains(task)) {
                todo.setStatus(TodoStatus.IN_PROGRESS);
                break;
            }
        }
    }

    /**
     * Get the next pending todo by priority.
     */
    public Todo getNextPending() {
        return todos.stream()
            .filter(t -> t.getStatus() == TodoStatus.PENDING)
            .sorted((a, b) -> Integer.compare(b.getPriority(), a.getPriority()))
            .findFirst()
            .orElse(null);
    }

    /**
     * Check if all todos are complete.
     */
    public boolean allComplete() {
        return todos.stream().allMatch(t -> t.getStatus() == TodoStatus.COMPLETE);
    }

    /**
     * Get count of pending todos.
     */
    public int getPendingCount() {
        return (int) todos.stream().filter(t -> t.getStatus() == TodoStatus.PENDING).count();
    }

    /**
     * Format todos for LLM prompt (markdown checklist).
     */
    public String formatForPrompt() {
        if (todos.isEmpty()) {
            return "No specific investigation steps defined yet.";
        }

        StringBuilder sb = new StringBuilder();
        for (Todo todo : todos) {
            String checkbox = switch (todo.getStatus()) {
                case COMPLETE -> "[x]";
                case IN_PROGRESS -> "[~]";
                case PENDING -> "[ ]";
            };

            sb.append(checkbox).append(" ").append(todo.getTask());

            if (todo.getStatus() == TodoStatus.COMPLETE && todo.getEvidence() != null) {
                sb.append(" ✓");
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    /**
     * Get summary of completed todos with evidence.
     */
    public String getCompletedSummary() {
        return todos.stream()
            .filter(t -> t.getStatus() == TodoStatus.COMPLETE)
            .map(t -> "✓ " + t.getTask() + (t.getEvidence() != null ? ": " + t.getEvidence() : ""))
            .collect(Collectors.joining("\n"));
    }

    /**
     * Compact representation for summarization.
     */
    public String toCompactString() {
        long completed = todos.stream().filter(t -> t.getStatus() == TodoStatus.COMPLETE).count();
        return String.format("%d/%d tasks complete", completed, todos.size());
    }

    public List<Todo> getAllTodos() {
        return new ArrayList<>(todos);
    }

    public String getObjective() {
        return objective;
    }
}
