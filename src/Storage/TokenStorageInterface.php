<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\Storage;

interface TokenStorageInterface
{
    /**
     * Retrieve stored token
     * Return null if not found.
     */
    public function retrieveToken(): ?string;
}
