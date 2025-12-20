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
     * Update todo list based on reflection feedback.
     * Adds new tasks if they're not duplicates, removes obsolete pending tasks.
     * Returns true if any changes were made (triggers iteration budget extension).
     *
     * @param newTasks Tasks to add (from reflection ADD)
     * @param removeTasks Tasks to remove (from reflection REMOVE)
     * @return true if todo list was modified
     */
    public boolean updateFromReflection(List<String> newTasks, List<String> removeTasks) {
        boolean changed = false;

        // Add new tasks if not duplicates
        if (newTasks != null && !newTasks.isEmpty()) {
            for (String newTask : newTasks) {
                // Skip "None" markers
                if (newTask == null || newTask.trim().isEmpty() ||
                    newTask.trim().equalsIgnoreCase("None")) {
                    continue;
                }

                // Check for duplicates using similarity
                boolean isDuplicate = false;
                for (Todo existing : todos) {
                    if (tasksSimilar(existing.getTask(), newTask)) {
                        isDuplicate = true;
                        break;
                    }
                }

                if (!isDuplicate) {
                    // Add with medium priority (5)
                    todos.add(new Todo(newTask.trim(), 5));
                    changed = true;
                }
            }
        }

        // Remove obsolete pending tasks
        if (removeTasks != null && !removeTasks.isEmpty()) {
            for (String removeTask : removeTasks) {
                // Skip "None" markers
                if (removeTask == null || removeTask.trim().isEmpty() ||
                    removeTask.trim().equalsIgnoreCase("None")) {
                    continue;
                }

                // Find and remove matching PENDING tasks only
                boolean removed = todos.removeIf(todo ->
                    todo.getStatus() == TodoStatus.PENDING &&
                    tasksSimilar(todo.getTask(), removeTask)
                );

                if (removed) {
                    changed = true;
                }
            }
        }

        return changed;
    }

    /**
     * Check if two tasks are similar (for duplicate detection).
     * Uses simple heuristics: lowercase comparison, contains relationship.
     *
     * @param task1 First task
     * @param task2 Second task
     * @return true if tasks are similar
     */
    private boolean tasksSimilar(String task1, String task2) {
        if (task1 == null || task2 == null) {
            return false;
        }

        // Normalize: lowercase, remove punctuation
        String normalized1 = task1.toLowerCase().replaceAll("[^a-z0-9\\s]", "").trim();
        String normalized2 = task2.toLowerCase().replaceAll("[^a-z0-9\\s]", "").trim();

        // Exact match after normalization
        if (normalized1.equals(normalized2)) {
            return true;
        }

        // Contains relationship (one is substring of other)
        if (normalized1.contains(normalized2) || normalized2.contains(normalized1)) {
            return true;
        }

        // Check word overlap (at least 70% common words)
        String[] words1 = normalized1.split("\\s+");
        String[] words2 = normalized2.split("\\s+");

        int commonWords = 0;
        for (String word1 : words1) {
            for (String word2 : words2) {
                if (word1.equals(word2) && word1.length() > 2) { // Skip short words
                    commonWords++;
                    break;
                }
            }
        }

        int maxWords = Math.max(words1.length, words2.length);
        double overlap = maxWords > 0 ? (double) commonWords / maxWords : 0;

        return overlap >= 0.7;
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
                case IN_PROGRESS -> "[->]";
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
