<?php

namespace DBAuth\Console;

use Config;
use Winter\Storm\Console\Command;

class SetupAccess extends Command
{
    /**
     * @var string The console command name.
     */
    protected static $defaultName = 'dbauth:setup-access';

    /**
     * @var string The name and signature of this command.
     */
    protected $signature = 'dbauth:setup-access';

    /**
     * @var string The console command description.
     */
    protected $description = 'Setup the database for DBAuth access';

    /**
     * Execute the console command.
     * @return void
     */
    public function handle()
    {
    }

    // TODO: Provide autocomplete suggestions for the "myCustomArgument" argument
    // public function suggestMyCustomArgumentValues(): array
    // {
    //     return ['value', 'another'];
    // }
}
