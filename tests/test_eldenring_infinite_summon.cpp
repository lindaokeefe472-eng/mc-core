#include <gtest/gtest.h>

#include "eldenring_sigscan.hpp"
#include "eldenring_infinite_summon.hpp"

#include <vector>
#include <fstream>

using namespace eldenring;

// 1. Signature Tests for CSBuddyMan DismissAll (0x1404BB9A0) and WorldChrMan RemoveBuddy (0x14050B340)
TEST(InfiniteSummon, CSBuddyDismissAllSignatureLengthAndFormat) {
    const auto sig = live::Signature::parse(live::sigs::kCSBuddyDismissAll);
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->size(), 32u);
}

TEST(InfiniteSummon, WorldChrManRemoveBuddySignatureLengthAndFormat) {
    const auto sig = live::Signature::parse(live::sigs::kWorldChrManRemoveBuddy);
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->size(), 32u);
}

// 2. Behavioral Gate Tests (TDD for dismissal suppression and decoupling)
TEST(InfiniteSummon, DismissalSuppressionDecision) {
    // Under Minecraft mode: dismissal MUST be suppressed (skip killing previous summons and avoid freeing tracking nodes)
    EXPECT_TRUE(summon::shouldSuppressDismissal(/*mc_mode=*/true, /*spawn_egg_active=*/false));
    EXPECT_TRUE(summon::shouldSuppressDismissal(/*mc_mode=*/true, /*spawn_egg_active=*/true));
    EXPECT_TRUE(summon::shouldSuppressDismissal(/*mc_mode=*/false, /*spawn_egg_active=*/true));

    // Under vanilla mode without spawn egg: dismissal MUST be preserved for authentic spirit ashes
    EXPECT_FALSE(summon::shouldSuppressDismissal(/*mc_mode=*/false, /*spawn_egg_active=*/false));
}

TEST(InfiniteSummon, DecouplingPolicyDecisions) {
    // A fresh summon spawned in MC mode must be decoupled from CSBuddyMan tracking to prevent heap collisions
    EXPECT_TRUE(summon::shouldDecoupleSummon(/*mc_mode=*/true, /*is_spirit_ash=*/true));
    EXPECT_FALSE(summon::shouldDecoupleSummon(/*mc_mode=*/false, /*is_spirit_ash=*/true));
    EXPECT_FALSE(summon::shouldDecoupleSummon(/*mc_mode=*/true, /*is_spirit_ash=*/false));
}

// 3. Timing and Cooldown Tests
TEST(InfiniteSummon, CooldownTimingIsReducedFrom3000msTo200ms) {
    EXPECT_LE(summon::kFastSummonCooldownMs, 200u);
    EXPECT_GT(summon::kFastSummonCooldownMs, 0u);

    // Timing simulation
    uint64_t last_ms = 1000;
    auto can_summon = [&](uint64_t now) {
        return (now - last_ms) >= summon::kFastSummonCooldownMs;
    };

    EXPECT_FALSE(can_summon(1000));
    EXPECT_FALSE(can_summon(1100)); // 100ms: rejected
    EXPECT_FALSE(can_summon(1199)); // 199ms: rejected
    EXPECT_TRUE(can_summon(1200));  // 200ms: accepted!
    EXPECT_TRUE(can_summon(2000));  // 1000ms: accepted!
}

// 4. Request Queue Monotonicity & Capacity
TEST(InfiniteSummon, QueueSmoothsRapidClicksMonotonically) {
    summon::SummonQueue q;
    EXPECT_EQ(q.size(), 0u);
    EXPECT_FALSE(q.try_pop().has_value());

    // Rapid clicking 5 spawn eggs
    for (int32_t req = 20001; req <= 20005; ++req) {
        q.enqueue(req);
    }
    EXPECT_EQ(q.size(), 5u);

    // Monotonic FIFO consumption per tick
    for (int32_t req = 20001; req <= 20005; ++req) {
        auto popped = q.try_pop();
        ASSERT_TRUE(popped.has_value());
        EXPECT_EQ(*popped, req);
    }
    EXPECT_EQ(q.size(), 0u);
    EXPECT_FALSE(q.try_pop().has_value());
}

TEST(InfiniteSummon, QueueCapacityClampedAtEngineLimit) {
    summon::SummonQueue q;
    // Capacity should be aligned with Dantelion engine max slots (60)
    EXPECT_EQ(summon::SummonQueue::kMaxQueueCapacity, 60u);

    for (size_t i = 0; i < 100; ++i) {
        q.enqueue(static_cast<int32_t>(i + 1));
    }
    EXPECT_EQ(q.size(), 60u);
}
