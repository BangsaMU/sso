<?php

namespace App\Services\Ai;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class GeminiProvider implements AiProviderInterface
{
    protected $apiKey;
    protected $apiUrl;
    protected $model;

    public function __construct()
    {
        $this->apiKey = config('gemini.api_key');
        $this->apiUrl = config('gemini.api_url');
        $this->model = config('gemini.model', 'gemini-1.5-flash');
    }

    public function sendMessage(array $history, string $systemPrompt): array
    {
        $apiContents = $this->formatHistory($history, $systemPrompt);

        // Standard Gemini Endpoint (v1beta)
        $url = "{$this->apiUrl}/models/{$this->model}:generateContent?key={$this->apiKey}";
        
        // Handle "v1" vs "v1beta" difference in base URL if needed, mostly config based.
        // If config includes full version path, use it. If not, default to standard.
        // The config `api_url` is `https://generativelanguage.googleapis.com/v1`.
        // But the controller used `v1beta`.
        // Let's force v1beta for now to match Controller logic if strictly needed, 
        // or rely on config if it's correct.
        // Controller used: https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent
        
        // Let's standardize to use the configured model and v1beta as it has better tool support generally.
        // But let's check config('gemini.api_url') usage.
        $baseUrl = "https://generativelanguage.googleapis.com/v1beta";

        $response = Http::retry(3, 1000)->timeout(30)->post("{$baseUrl}/models/{$this->model}:generateContent?key={$this->apiKey}", [
            'contents' => $apiContents,
            'generationConfig' => config('gemini.generation_config', [
                'temperature' => 0.7,
                'maxOutputTokens' => 1024,
            ]),
        ]);

        if (! $response->successful()) {
            Log::error('Gemini API Error', ['status' => $response->status(), 'body' => $response->body()]);
            throw new \Exception('Gemini API Error: ' . $response->status());
        }

        $data = $response->json();
        $text = $data['candidates'][0]['content']['parts'][0]['text'] ?? 'No text response';

        return ['text' => $text, 'raw' => $data];
    }

    protected function formatHistory(array $history, string $systemPrompt): array
    {
        // Gemini doesn't support "system" role in `contents` effectively in all versions,
        // but often we pass it as the first user part or dedicated system_instruction.
        // Controller approach: User (Prompt) -> Model (Ack) -> History
        
        $contents = [];
        
        // System Prompt Trick
        $contents[] = ['role' => 'user', 'parts' => [['text' => $systemPrompt]]];
        $contents[] = ['role' => 'model', 'parts' => [['text' => 'Understood.']]];

        foreach ($history as $msg) {
            $role = $msg['role'] === 'user' ? 'user' : 'model';
            $text = $msg['content'] ?? '';
            
            $contents[] = [
                'role' => $role,
                'parts' => [['text' => $text]]
            ];
        }

        return $contents;
    }
}
