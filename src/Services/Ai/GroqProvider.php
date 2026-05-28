<?php

namespace App\Services\Ai;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class GroqProvider implements AiProviderInterface
{
    protected $apiKey;
    protected $apiUrl;
    protected $model;

    public function __construct()
    {
        $this->apiKey = config('groq.api_key');
        $this->apiUrl = config('groq.api_url');
        $this->model = config('groq.model', 'mixtral-8x7b-32768');
    }

    public function sendMessage(array $history, string $systemPrompt): array
    {
        $messages = $this->formatHistory($history, $systemPrompt);

        $response = Http::retry(3, 1000)->withToken($this->apiKey)->timeout(30)->post("{$this->apiUrl}/chat/completions", [
            'model' => $this->model,
            'messages' => $messages,
            'temperature' => (float) config('groq.temperature', 0.7),
            'max_tokens' => (int) config('groq.max_tokens', 1024),
        ]);

        if (! $response->successful()) {
            Log::error('Groq API Error', ['status' => $response->status(), 'body' => $response->body()]);
            throw new \Exception('Groq API Error: ' . $response->status());
        }

        $data = $response->json();
        $text = $data['choices'][0]['message']['content'] ?? 'No text response';

        return ['text' => $text, 'raw' => $data];
    }

    protected function formatHistory(array $history, string $systemPrompt): array
    {
        $messages = [];
        
        // System Message
        $messages[] = ['role' => 'system', 'content' => $systemPrompt];

        foreach ($history as $msg) {
            $role = $msg['role'] === 'user' ? 'user' : 'assistant';
            $messages[] = [
                'role' => $role,
                'content' => $msg['content'] ?? ''
            ];
        }

        return $messages;
    }
}
