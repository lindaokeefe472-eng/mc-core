#pragma once

#include <cstdint>
#include <deque>
#include <mutex>
#include <atomic>
#include <optional>

namespace eldenring::summon {

// The cooldown is shortened from the engine/adapter default 3000ms down to 200ms
// to allow responsive successive spawn egg usage without dropped clicks.
constexpr uint64_t kFastSummonCooldownMs = 200;

// Maximum concurrent summon slots supported natively by Dantelion ChrSpawner:
// 6 groups * 10 slots = 60 entities.
constexpr size_t kMaxSummonCapacity = 60;

/**
 * Gate deciding whether CSBuddyMan pre-dismissal call (0x1404BB9A0) should be bypassed.
 * When in Minecraft mode or when a spawn egg request is triggered, existing summons must remain alive.
 * In vanilla mode without spawn eggs, the original dismissal logic executes to maintain authentic spirit ash behavior.
 */
inline bool shouldSuppressDismissal(bool mc_mode, bool spawn_egg_active) {
    return mc_mode || spawn_egg_active;
}

/**
 * Gate deciding whether a freshly spawned entity should be decoupled from CSBuddyMan tracking.
 * When in Minecraft mode and the entity is a spawned ally, decoupling it prevents subsequent
 * dismissals from corrupting CS::ComManipulator message queues and chunk free coalescing.
 */
inline bool shouldDecoupleSummon(bool mc_mode, bool is_spirit_ash) {
    return mc_mode && is_spirit_ash;
}

/**
 * Thread-safe FIFO queue to smooth rapid spawn egg clicks across ticks without request drops.
 */
class SummonQueue {
public:
    static constexpr size_t kMaxQueueCapacity = kMaxSummonCapacity;

    void enqueue(int32_t request_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() < kMaxQueueCapacity) {
            queue_.push_back(request_id);
        }
    }

    std::optional<int32_t> try_pop() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) return std::nullopt;
        int32_t val = queue_.front();
        queue_.pop_front();
        return val;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.clear();
    }

private:
    mutable std::mutex mutex_;
    std::deque<int32_t> queue_;
};

} // namespace eldenring::summon
