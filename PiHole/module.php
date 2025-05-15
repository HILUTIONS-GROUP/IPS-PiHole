<?php

declare(strict_types=1);

class PiHole extends IPSModule
{
    public function Create()
    {
        //Never delete this line!
        parent::Create();

        // Instanz-Eigenschaften registrieren
        $this->RegisterPropertyString('Host', ''); // Pi-hole Host oder IP, Standard pi.hole
        $this->RegisterPropertyInteger('Port', 443); // Standardeinstellung Port 443
        $this->RegisterPropertyString('PihPassword', ''); // Pi-hole Passwort für API
        $this->RegisterPropertyInteger('UpdateTimerInterval', 20); // Intervall in Sekunden

        // Variablen registrieren
        $this->RegisterVariableBoolean('PihStatus', $this->Translate('Status'), '~Switch', 1);
        $this->EnableAction('PihStatus');
        $this->RegisterVariableInteger('PihDisableTime', $this->Translate('Time to disable'), '', 2);
        $this->EnableAction('PihDisableTime');
        $this->RegisterVariableInteger('PihBlockedDomains', $this->Translate('Blocked Domains'), '', 3);
        $this->RegisterVariableInteger('PihDNSQueriesToday', $this->Translate('DNS Queries Today'), '', 4);
        $this->RegisterVariableInteger('PihAdsBlockedToday', $this->Translate('Ads Blocked Today'), '', 5);
        $this->RegisterVariableInteger('PihQueriesCached', $this->Translate('Queries Cached'), '', 6);
        $this->RegisterVariableInteger('PihDNSQueriesAllTypes', $this->Translate('DNS Queries All Types'), '', 7);
        $this->RegisterVariableInteger('PihGravityLastUpdated', $this->Translate('Gravity Last Updated'), '~UnixTimestamp', 8);

        // Prozent-Variablenprofil für "Ads Percentage"
        if (!IPS_VariableProfileExists('PiHole.Percent')) {
            IPS_CreateVariableProfile('PiHole.Percent', 1);
            IPS_SetVariableProfileText('PiHole.Percent', '', ' %');
        }
        $this->RegisterVariableInteger('PihAdsPrecentageToday', $this->Translate('Ads Percentage Today'), 'PiHole.Percent', 9);

        // Variable speichern für Authentifizierung - SID (Session ID) und CSRF Token
        $this->RegisterVariableString('SID', $this->Translate('Session ID'), '', 10);
        $this->RegisterVariableString('CSRF', $this->Translate('CSRF Token'), '', 11);

        // Timer registrieren
        $this->RegisterTimer('Pih_updateStatus', 0, 'Pih_updateStatus($_IPS[\'TARGET\']);');
    }

    public function ApplyChanges()
    {
        //Never delete this line!
        parent::ApplyChanges();

        if ($this->ReadPropertyString('Host') != '') {
            $this->SetTimerInterval('Pih_updateStatus', $this->ReadPropertyInteger('UpdateTimerInterval') * 1000);
        } else {
            $this->SetTimerInterval('Pih_updateStatus', 0);
        }

        // Authentifizierung
        $password = $this->ReadPropertyString('PihPassword');
        if (!empty($password)) {
            $this->authenticate($password);
        }
    }

    public function updateStatus()
    {
        $sid = $this->GetValue('SID');
        if (empty($sid)) {
            $this->SendDebug(__FUNCTION__, 'SID is missing. Authentication required.', 0);
            echo 'SID is missing. Authenticate first.';
            return;
        }

        $this->getSummary($sid);
    }

    public function setActive(bool $value)
    {
        $sid = $this->GetValue('SID');
        if (empty($sid)) {
            $this->SendDebug(__FUNCTION__, 'SID is missing. Authentication required.', 0);
            echo 'SID is missing. Authenticate first.';
            return;
        }

        $this->setEnabled($value, $sid);
    }

    private function getSummary(string $sid)
    {
        // Hole den aktuellen Blocking-Status
        $blockingData = $this->request('dns/blocking', $sid);
        if ($blockingData !== null && isset($blockingData['blocking'])) {
            $this->SetValue('PihStatus', $blockingData['blocking'] === 'enabled');

            // Wenn Timer gesetzt ist
            if (isset($blockingData['timer']) && $blockingData['timer'] !== null) {
                $remainingTime = max(0, floor(($blockingData['timer'] - time()) / 60));
                $this->SetValue('PihDisableTime', $remainingTime);
            }
        }

        // Hole die History-Daten für die letzten 24 Stunden
        $historyData = $this->request('history', $sid);
        if ($historyData !== null && isset($historyData['history'])) {
            $lastHour = end($historyData['history']);
            if ($lastHour) {
                $this->SetValue('PihDNSQueriesToday', $lastHour['total']);
                $this->SetValue('PihAdsBlockedToday', $lastHour['blocked']);
                $this->SetValue('PihQueriesCached', $lastHour['cached']);
                if ($lastHour['total'] > 0) {
                    $this->SetValue('PihAdsPrecentageToday', round(($lastHour['blocked'] / $lastHour['total']) * 100, 2));
                }
            }
        }
    }

    public function RequestAction($Ident, $Value)
    {
        switch ($Ident) {
            case 'PihStatus':
                $this->setActive($Value);
                break;
            case 'PihDisableTime':
                $this->SetValue($Ident, $Value);
                break;
        }
    }

    private function setEnabled(bool $enabled, string $sid)
    {
        $url = 'http://' . $this->ReadPropertyString('Host') . ':' . $this->ReadPropertyInteger('Port') . '/api/dns/blocking/';
        $url .= $enabled ? 'enable' : 'disable';

        // Wenn deaktiviert wird und eine Zeit gesetzt ist
        if (!$enabled) {
            $time = $this->GetValue('PihDisableTime');
            if ($time > 0) {
                $url .= '/' . $time;
            }
        }

        // Füge SID als Query-Parameter hinzu
        $url .= '?sid=' . urlencode($sid);

        $options = [
            'http' => [
                'method'  => 'GET',
                'header'  => "Accept: application/json\r\n",
                'ignore_errors' => true
            ]
        ];

        $context = stream_context_create($options);
        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            $this->SendDebug(__FUNCTION__, 'Failed to change blocking status', 0);
            echo 'Failed to change blocking status.';
            return;
        }

        $decodedResponse = json_decode($response, true);
        if ($decodedResponse !== null && isset($decodedResponse['status']) && $decodedResponse['status'] === 'success') {
            $this->SetValue('PihStatus', $enabled);
            $this->SendDebug(__FUNCTION__, 'Successfully changed blocking status to: ' . ($enabled ? 'enabled' : 'disabled'), 0);
        } else {
            $this->SendDebug(__FUNCTION__, 'Failed to change blocking status. Response: ' . $response, 0);
            echo 'Failed to change blocking status.';
        }
    }

    private function authenticate(string $password): bool
    {
        $url = 'https://' . $this->ReadPropertyString('Host') . ':' . $this->ReadPropertyInteger('Port') . '/api/auth';

        $postData = json_encode(['password' => $password]);

        $options = [
            'http' => [
                'method'  => 'POST',
                'header'  => "Content-Type: application/json\r\n" .
                    "Content-Length: " . strlen($postData) . "\r\n",
                'content' => $postData,
                'ignore_errors' => true
            ],
            'ssl' => [
                'verify_peer'      => false,
                'verify_peer_name' => false
            ]
        ];

        $context = stream_context_create($options);
        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            $this->SendDebug(__FUNCTION__, 'Authentication failed: Unable to contact API.', 0);
            echo 'Authentication failed: Unable to contact the API.';
            return false;
        }

        $decodedResponse = json_decode($response, true);
        if (isset($decodedResponse['session'])) {
            $session = $decodedResponse['session'];
            if ($session['valid']) {
                $this->SetValue('SID', $session['sid']);
                $this->SetValue('CSRF', $session['csrf']);
                $this->SendDebug(__FUNCTION__, 'Authentication successful.', 0);
                return true;
            }
        }

        $this->SendDebug(__FUNCTION__, 'Authentication failed: Invalid response.', 0);
        echo 'Authentication failed: Invalid response.';
        return false;
    }

    private function request(string $endpoint, string $sid)
    {
        $url = 'http://' . $this->ReadPropertyString('Host') . ':' . $this->ReadPropertyInteger('Port') . '/api/' . $endpoint;

        // Füge SID als Query-Parameter hinzu
        $separator = strpos($url, '?') === false ? '?' : '&';
        $url .= $separator . 'sid=' . urlencode($sid);

        $this->SendDebug(__FUNCTION__ . ' URL', $url, 0);

        $options = [
            'http' => [
                'method'  => 'GET',
                'header'  => "Accept: application/json\r\n",
                'ignore_errors' => true
            ]
        ];

        $context = stream_context_create($options);
        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            $this->SendDebug(__FUNCTION__, 'Failed to reach API endpoint: ' . $endpoint, 0);
            echo 'Request failed: Unable to contact the API.';
            return null;
        }

        $this->SendDebug(__FUNCTION__ . ' Response', $response, 0);

        $decodedResponse = json_decode($response, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->SendDebug(__FUNCTION__, 'Invalid JSON response: ' . json_last_error_msg(), 0);
            echo 'Request failed: Invalid JSON response.';
            return null;
        }

        return $decodedResponse;
    }
}