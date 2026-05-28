<?php

namespace App\Services\Ai;

use App\Models\ChatLog;
use Illuminate\Support\Facades\Log;

class AiChatService
{
    protected $provider;
    protected $maxContextMessages = 10; // Keeping it small to reduce tokens

    public function __construct()
    {
        $this->resolveProvider();
    }

    protected function resolveProvider()
    {
        $groqKey = config('groq.api_key');
        
        if ($groqKey) {
            $this->provider = new GroqProvider();
        } else {
            $this->provider = new GeminiProvider();
        }
    }

    public function sendMessage(array $history, string $systemPrompt): array
    {
        // 1. Optimize Context (Token Reduction)
        // We only send the last N messages to the API, plus the system prompt.
        $optimizedHistory = $this->optimizeContext($history);

        // 2. Call Provider
        $result = $this->provider->sendMessage($optimizedHistory, $systemPrompt);

        return $result;
    }

    /**
     * Store a message in the database.
     */
    public function logMessage(int $userId, string $role, string $content, ?array $toolCalls = null, ?string $sessionId = null)
    {
        return ChatLog::create([
            'user_id' => $userId,
            'session_id' => $sessionId,
            'role' => $role,
            'content' => $content,
            'tool_calls' => $toolCalls,
        ]);
    }

    /**
     * Retrieve full history from database for a specific session.
     */
    public function getHistory(int $userId, ?string $sessionId = null)
    {
        $query = ChatLog::where('user_id', $userId)->orderBy('created_at', 'asc');
        
        if ($sessionId) {
            $query->where('session_id', $sessionId);
        }

        return $query->get()->map(function ($log) {
                return [
                    'role' => $log->role,
                    'content' => $log->content,
                    'created_at' => $log->created_at->toIso8601String(),
                ];
            })
            ->toArray();
    }
    
    /**
     * Get list of user's sessions.
     */
    public function getSessions(int $userId)
    {
        // Get unique session_ids with the first message as a "title" equivalent and the time of the last message
        // A bit complex query to get efficient aggregate.
        // Simplification: Select distinct session_id, max(created_at).
        // For title, we could fetch separately or just use "Chat [Date]".
        // Let's try to get the first user message for title.
        
        // Step 1: Get sessions ordered by last update
        $sessions = ChatLog::where('user_id', $userId)
            ->whereNotNull('session_id')
            ->select('session_id')
            ->selectRaw('MAX(created_at) as last_activity')
            ->groupBy('session_id')
            ->orderByDesc('last_activity')
            ->get();
            
        // Step 2: Enrich with "Title" (first User message)
        // We can optimize this later if N+1 is an issue, but for a chatbot history it's likely fine.
        return $sessions->map(function ($session) use ($userId) {
            $firstMsg = ChatLog::where('user_id', $userId)
                ->where('session_id', $session->session_id)
                ->where('role', 'user')
                ->orderBy('created_at', 'asc')
                ->first();
                
            $title = $firstMsg ? substr($firstMsg->content, 0, 30) . '...' : 'New Chat';
            
            return [
                'id' => $session->session_id,
                'title' => $title,
                'last_activity' => $session->last_activity,
            ];
        });
    }

    /**
     * Clear history for a user or session.
     */
    public function clearHistory(int $userId, ?string $sessionId = null)
    {
        $query = ChatLog::where('user_id', $userId);
        if ($sessionId) {
            $query->where('session_id', $sessionId);
        }
        return $query->delete();
    }

    protected function optimizeContext(array $fullHistory)
    {
        // If history is small, just return it
        if (count($fullHistory) <= $this->maxContextMessages) {
            return $fullHistory;
        }

        // Slice the last N messages
        // Ensure we don't break a tool-use chain if possible, but for now simple sliding window.
        // If the cut point splits a tool call and its result, the AI might get confused.
        // A smarter implementation would look for the last "user" message and cut before that if needed.
        // But for "22k token" reduction, hard limit is safest first step.
        
        return array_slice($fullHistory, -$this->maxContextMessages);
    }
}
