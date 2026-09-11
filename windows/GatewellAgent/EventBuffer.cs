using System.Collections.Concurrent;

namespace GatewellAgent;

/// <summary>
/// Bounded in-memory buffer for security events. Each entry carries a unique
/// event_id used by the platform for dedupe, so a failed flush can be retried
/// without creating duplicates. Oldest entries are dropped when the cap is hit
/// so the agent can never grow unbounded while the platform is unreachable.
/// </summary>
public sealed class EventBuffer
{
    private const int Capacity = 5000;

    private readonly ConcurrentQueue<Dictionary<string, object?>> _queue = new();
    private readonly AgentLog _log;
    private long _dropped;

    public EventBuffer(AgentLog log) => _log = log;

    public int Count => _queue.Count;

    public void Add(string eventType, string severity, string description)
    {
        while (_queue.Count >= Capacity && _queue.TryDequeue(out _))
            Interlocked.Increment(ref _dropped);

        _queue.Enqueue(new Dictionary<string, object?>
        {
            ["event_id"]    = Guid.NewGuid().ToString(),
            ["event_type"]  = eventType,
            ["severity"]    = severity,
            ["description"] = description,
            ["timestamp"]   = DateTime.UtcNow.ToString("o")
        });
    }

    /// <summary>Removes up to MaxEventsPerBatch entries for sending.</summary>
    public List<object> TakeBatch()
    {
        var batch = new List<object>(Config.MaxEventsPerBatch);
        while (batch.Count < Config.MaxEventsPerBatch && _queue.TryDequeue(out var e))
            batch.Add(e);
        return batch;
    }

    /// <summary>Puts an unsent batch back at the head for the next flush.</summary>
    public void Requeue(IEnumerable<object> batch)
    {
        foreach (var item in batch)
            if (item is Dictionary<string, object?> d)
                _queue.Enqueue(d);
    }

    public void LogDropStats()
    {
        var dropped = Interlocked.Exchange(ref _dropped, 0);
        if (dropped > 0)
            _log.Warn($"Dropped {dropped} buffered events (buffer at capacity).");
    }
}
