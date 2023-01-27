<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\RequestHandler;

use CrowdSec\Common\Client\RequestHandler\FileGetContents as CommonFileGetContents;

/**
 * File_get_contents request handler.
 *
 * @author    CrowdSec team
 *
 * @see      https://crowdsec.net CrowdSec Official Website
 *
 * @copyright Copyright (c) 2022+ CrowdSec
 * @license   MIT License
 *
 * @deprecated since 1.1.0: use CrowdSec\Common\Client\RequestHandler\FileGetContents instead
 *
 * @todo remove in 2.0.0
 */
class FileGetContents extends CommonFileGetContents implements RequestHandlerInterface
{
}
