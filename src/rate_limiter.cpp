#include "rate_limiter.hpp"

#include <algorithm> // min
#include <cassert>

namespace tide {

// -- rate_limiter --

void rate_limiter::set_max_rate(const int channel, const int n)
{
    assert(n == unlimited || n > 0);
    max_quotas_[channel] = n;
    if((n != unlimited) || (quotas_[channel] > n))
        quotas_[channel] = n;
}

void rate_limiter::add_quota(const int channel, const int n)
{
    // TODO does it make sense to set quota to 0, effectively blocking all traffic?
    assert(n == unlimited || n > 0);
    auto& quota = quotas_[channel];
    auto& max_quota = max_quotas_[channel];
    if(n == unlimited)
    {
        quota = unlimited;
        max_quota = unlimited;
    }
    else if(quota != unlimited)
    {
        quota += n;
        if((max_quota != unlimited) && (quota > max_quota))
        {
            quota = max_quota;
        }
    }
    // There may be entities waiting for quota. Since the quota has been increased,
    // distribute it.
    while(!quota_requester_queues_[channel].empty()
          && ((quota == unlimited) || (quota > 0)))
    {
        auto& requester = quota_requester_queues_[channel].front();
        if(quota == unlimited)
        {
            requester.handler(requester.num_desired_bytes);
        }
        else
        {
            const int q = std::min(quota, requester.num_desired_bytes);
            quota -= q;
            requester.handler(q);
        }
        quota_requester_queues_[channel].pop_front();
    }
}

void rate_limiter::subtract_quota(const int channel, const int n)
{
    assert(n == unlimited || n > 0);
    if(quotas_[channel] != unlimited)
    {
        if(n == unlimited)
            quotas_[channel] = 0;
        else
            quotas_[channel] -= n;
    }
}

int rate_limiter::request_quota(const int channel, const int num_desired_bytes)
{
    int& quota = quotas_[channel];
    if(quota == unlimited) { return num_desired_bytes; }
    const int r = std::min(num_desired_bytes, quota);
    quota -= r;
    return r;
}

void rate_limiter::subscribe_for_quota(const int channel, const token_type token,
    const int num_desired_bytes, std::function<void(int)> handler)
{
    auto& requester_queue = quota_requester_queues_[channel];
    // TODO maybe switch to a map based structure for the requester queues
    auto requester = std::find_if(requester_queue.begin(), requester_queue.end(),
        [&token](const auto& r) { return r.token == token; });
    if(requester == requester_queue.end())
    {
        quota_requester requester;
        requester.token = token;
        requester.num_desired_bytes = num_desired_bytes;
        requester.handler = std::move(handler);
        requester_queue.emplace_back(std::move(requester));
    }
    else
    {
        requester->num_desired_bytes = num_desired_bytes;
    }
}

void rate_limiter::unsubscribe(const token_type token)
{
    for(auto& queue : quota_requester_queues_)
    {
        auto it = std::find_if(queue.begin(), queue.end(),
            [&token](const auto& r) { return r.token == token; });
        if(it != queue.end()) { queue.erase(it); }
    }
}

// -- torrent_rate_limiter --

void torrent_rate_limiter::add_download_quota(const int quota)
{
    if(is_detached_) { rate_limiter::add_download_quota(quota); }
}

void torrent_rate_limiter::add_upload_quota(const int quota)
{
    if(is_detached_) { rate_limiter::add_upload_quota(quota); }
}

void torrent_rate_limiter::subtract_download_quota(const int quota)
{
    if(is_detached_) { rate_limiter::subtract_download_quota(quota); }
}

void torrent_rate_limiter::subtract_upload_quota(const int quota)
{
    if(is_detached_) { rate_limiter::subtract_upload_quota(quota); }
}

void torrent_rate_limiter::set_max_download_rate(const int max)
{
    if(is_detached_) { rate_limiter::set_max_download_rate(max); }
}

void torrent_rate_limiter::set_max_upload_rate(const int max)
{
    if(is_detached_) { rate_limiter::set_max_upload_rate(max); }
}

int torrent_rate_limiter::request_download_quota(const int num_desired_bytes)
{
    if(is_detached_)
        return rate_limiter::request_download_quota(num_desired_bytes);
    else
        return global_rate_limiter.request_download_quota(num_desired_bytes);
}

int torrent_rate_limiter::request_upload_quota(const int num_desired_bytes)
{
    if(is_detached_)
        return rate_limiter::request_upload_quota(num_desired_bytes);
    else
        return global_rate_limiter.request_upload_quota(num_desired_bytes);
}

void torrent_rate_limiter::subscribe_for_download_quota(const token_type token,
    const int num_desired_bytes, std::function<void(int)> handler)
{
    if(is_detached_)
        rate_limiter::subscribe_for_download_quota(
            token, num_desired_bytes, std::move(handler));
    else
        global_rate_limiter.subscribe_for_download_quota(
            token, num_desired_bytes, std::move(handler));
}

void torrent_rate_limiter::subscribe_for_upload_quota(const token_type token,
    const int num_desired_bytes, std::function<void(int)> handler)
{
    if(is_detached_)
        rate_limiter::subscribe_for_upload_quota(
            token, num_desired_bytes, std::move(handler));
    else
        global_rate_limiter.subscribe_for_upload_quota(
            token, num_desired_bytes, std::move(handler));
}

void torrent_rate_limiter::unsubscribe(const token_type token)
{
    rate_limiter::unsubscribe(token);
    global_rate_limiter.unsubscribe(token);
}

} // tide
