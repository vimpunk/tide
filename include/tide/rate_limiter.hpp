#ifndef TIDE_RATE_LIMITER_HEADER
#define TIDE_RATE_LIMITER_HEADER

#include <functional> // function
#include <deque>

namespace tide {

/**
 * This class acts as a container for (upload and download) bandwidth quota, which needs
 * to be periodically refilled, after which network entities can then request quota
 * which they can use.
 *
 * All values are in bytes.
 */
struct rate_limiter
{
    // A unique value used to identify a bandwidth quota requester.
    using token_type = void*;
    constexpr static int unlimited = -1;

protected:

    /** Used to index into quotas_, max_quotas_, and quota_requester_queues_. */
    enum channel { download, upload };

    // The available bandwidth quota until it is refilled.
    int quotas_[2] = {unlimited, unlimited};

    // We need a maximum quota, as otherwise, if not much traffic is exchanged, the quota
    // would accumulate indefinitely, and when data starts to be exchanged then possibly
    // more data may be transferred than the desired per second cap.
    int max_quotas_[2] = {unlimited, unlimited};

    /**
     * It's possible that an entity requesting bandwidth quota will not receive any if
     * the time slot's quota has been drained. This may cause issues with halting
     * asynchronous callback chains, so it is possible to register a handler which is
     * invoked once more bandwidth quota is available, enabling the asynchronous entity
     * to continue its cycle.
     */
    struct quota_requester
    {
        token_type token;
        int num_desired_bytes;
        std::function<void(int)> handler;
    };

    // All entities that have subscribed for bandwidth quota.
    std::deque<quota_requester> quota_requester_queues_[2];

public:

    int download_quota() const noexcept { return quotas_[download]; }
    int upload_quota() const noexcept { return quotas_[upload]; }
    int max_download_quota() const noexcept { return max_quotas_[download]; }
    int max_upload_quota() const noexcept { return max_quotas_[upload]; }

    /**
     * Increases bandwidth quota by `n` bytes, but will not cause values to exceed
     * their respective maximums.
     *
     * If `n` is `unlimited`, the internal value and its corresponding maximum
     * values are both set to `unlimited`.
     */
    void add_download_quota(const int n) { add_quota(download, n); }
    void add_upload_quota(const int n) { add_quota(upload, n); }

    /** Subtracts bandwidth quota by `n` bytes. */
    void subtract_download_quota(const int n) { subtract_quota(download, n); }
    void subtract_upload_quota(const int n) { subtract_quota(upload, n); }

    /**
     * Sets max quota to `n` and if `n` is not `unlimited` and the current quota
     * exceeds `n`, quota is also set to `n.
     */
    void set_max_download_rate(const int n) { set_max_rate(download, n); }
    void set_max_upload_rate(const int n) { set_max_rate(upload, n); }

    /** Returns `num_desired_bytes` or less quota. */
    int request_download_quota(const int num_desired_bytes)
    {
        return request_quota(download, num_desired_bytes);
    }

    int request_upload_quota(const int num_desired_bytes)
    {
        return request_quota(upload, num_desired_bytes);
    }

    /** Invokes `handler` when new quota is added if quota is 0. Does nothing otherwise. */
    void subscribe_for_download_quota(const token_type token,
        const int num_desired_bytes, std::function<void(int)> handler)
    {
        subscribe_for_quota(download, token, num_desired_bytes, std::move(handler));
    }

    void subscribe_for_upload_quota(const token_type token,
        const int num_desired_bytes, std::function<void(int)> handler)
    {
        subscribe_for_quota(upload, token, num_desired_bytes, std::move(handler));
    }

    /** Attempts to remove all handlers associated with `token`. */
    void unsubscribe(const token_type token);

private:

    void add_quota(const int channel, const int quota);
    void subtract_quota(const int channel, const int quota);
    void set_max_rate(const int channel, const int max);
    int request_quota(const int channel, const int num_desired_bytes);
    void subscribe_for_quota(const int channel, const token_type token,
        const int num_desired_bytes, std::function<void(int)> handler);
};

/**
 * The above class acts as a main/global bandwidth quota distributor of which only one
 * is used in engine, while this is per torrent based and distributes quota among its
 * peer sessions and, depending on whether it's detached from the global rate limiter,
 * is refilled with quota by its corresponding torrent and disregards the global rate
 * limiter, or requests quota from the global rate limiter.
 */
class torrent_rate_limiter : public rate_limiter
{
    // The global bandwidth controller from which this torrent_rate_limiter
    // requests and receives its quota.
    rate_limiter& global_rate_limiter;

    // A torrent may have separate rate limit settings, in which case it no longer
    // requests quota from the global limiter but instead metes out quota from its own
    // reserves, which `torrent` has to refill.
    bool is_detached_ = false;

public:

    torrent_rate_limiter(rate_limiter& rl) : global_rate_limiter(rl) {}

    /**
     * A torrent may be exempt from being rate limited by the global rate limiter
     * employed by `engine`. If this is the case, its downlink and uplink are both
     * detached from the global limiter.
     */
    bool is_detached_from_global_rate_limiter() { return is_detached_; }

    /**
     * `torrent_rate_limiter` no longer requests bandwidth quota from the global
     * rate limiter in `engine` and instead uses its own reserves, which its `torrent`
     * must periodically refill.
     */
    void detach_from_global_rate_limiter() { is_detached_ = true; }

    /**
     * Attaches this `torrent_rate_limiter` to the global rate limiter which then
     * requests bandwidth quota from it. `torrent` may not refill its bandwidth quota
     * from now on.
     */
    void attach_to_global_rate_limiter() { is_detached_ = false; }

    /** Only increases this instance's quota if it's detached. */
    void add_download_quota(const int quota);
    void add_upload_quota(const int quota);

    /** Only decreases this instance's quota if it's detached. */
    void subtract_download_quota(const int quota);
    void subtract_upload_quota(const int quota);

    void set_max_download_rate(const int max);
    void set_max_upload_rate(const int max);

    /**
     * If this instance is attached to the global bandwidth quota, this forwards the
     * request to that, otherwise serves requester from this instance's own reserves.
     */
    int request_download_quota(const int num_desired_bytes);
    int request_upload_quota(const int num_desired_bytes);

    /**
     * If this instance is attached to the global bandwidth quota, this hands over
     * `handler` to that, otherwise saves `handler` in its own wait queue. If `handler`
     * is not invoked when this instance is attached to the global rate limiter, the
     * `handler` is transferred to the rate limiter.
     *
     * FIXME if we're detached, register a handler, but then detached, the handler will
     * not be transfered back!
     */
    void subscribe_for_download_quota(const token_type token,
        const int num_desired_bytes, std::function<void(int)> handler);
    void subscribe_for_upload_quota(const token_type token,
        const int num_desired_bytes, std::function<void(int)> handler);

    void unsubscribe(const token_type token);
};

} // namespace tide

#endif // TIDE_RATE_LIMITER_HEADER
