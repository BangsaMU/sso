<?php

namespace App\Services;

use App\Models\Ticket;
use Illuminate\Support\Facades\DB;
use Carbon\Carbon;

class TicketNumberGenerator
{
    private const DATE_FORMAT = 'Y-m-d';
    private const PADDING = 4;

    public function generate(): string
    {
        return DB::transaction(function () {
            $date = Carbon::now()->format(self::DATE_FORMAT);
            $prefix = $date . '/';

            $lastTicket = Ticket::where('ticket_number', 'like', $prefix . '%')
                ->lockForUpdate()
                ->orderBy('ticket_number', 'desc')
                ->first();

            $nextNumber = $this->getNextNumber($lastTicket, $prefix);

            return $prefix . $nextNumber;
        });
    }

    private function getNextNumber(?Ticket $lastTicket, string $prefix): string
    {
        if (!$lastTicket) {
            return str_pad(1, self::PADDING, '0', STR_PAD_LEFT);
        }

        $lastNumber = substr($lastTicket->ticket_number, strlen($prefix));
        $nextNumber = intval($lastNumber) + 1;

        return str_pad($nextNumber, self::PADDING, '0', STR_PAD_LEFT);
    }

    public static function getTodayDate(): string
    {
        return Carbon::now()->format(self::DATE_FORMAT);
    }

    public static function isValidFormat(string $ticketNumber): bool
    {
        return preg_match('/^\d{4}-\d{2}-\d{2}\/\d{4}$/', $ticketNumber) === 1;
    }
}