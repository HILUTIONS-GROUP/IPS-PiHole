<?php

declare(strict_types=1);

class PiHole extends IPSModule
{
    public function Create()
    {
        //Never delete this line!
        parent::Create();

        // Instanz-Eigenschaften registrieren
        $this->RegisterPropertyString('Host', 'pi.hole'); // Pi-hole Host oder IP, Standard pi.hole
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

        // Variable speichern für Authentifizierung - SID (Session ID)
        $this->RegisterVariableString('SID', $this->Translate('Session ID'), '', 10);

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
        $summaryData = $this->request('summary', $sid);
        if ($summaryData != null) {
            $this->SetValue('PihBlockedDomains', $summaryData['domains_being_blocked']);
            $this->SetValue('PihDNSQueriesToday', $summaryData['dns_queries_today']);
            $this->SetValue('PihAdsBlockedToday', $summaryData['ads_blocked_today']);
            $this->SetValue('PihAdsPrecentageToday', round(($summaryData['ads_blocked_today'] / $summaryData['dns_queries_today']) * 100, 2));
            $this->SetValue('PihQueriesCached', $summaryData['queries_cached']);
            $this->SetValue('PihDNSQueriesAllTypes', $summaryData['dns_queries_all_types']);
        }

        $gravityData = $this->request('gravity', $sid);
        if ($gravityData != null && isset($gravityData['last_updated']['absolute'])) {
            $this->SetValue('PihGravityLastUpdated', $gravityData['last_updated']['absolute']);
        } else {
            $this->SendDebug(__FUNCTION__, 'Gravity last_updated absolute not found.', 0);
        }

        $statusData = $this->request('status', $sid);
        if ($statusData != null && isset($statusData['status'])) {
            $this->SetValue('PihStatus', $statusData['status'] === 'enabled');
        } else {
            $this->SendDebug(__FUNCTION__, 'Status not found.', 0);
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
        $endpoint = $enabled ? 'enable' : 'disable';
        // Time parameter is required for disable endpoint
        $time = ($endpoint === 'disable') ? '&time=' . $this->GetValue('PihDisableTime') : '';
        $data = $this->request($endpoint . $time, $sid);

        if ($data != null && isset($data['status']) && $data['status'] === 'success') {
            $this->SetValue('PihStatus', $enabled);
        } else {
            $this->SendDebug(__FUNCTION__, 'Failed to change status.', 0);
            echo 'Failed to change status.';
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
        if (isset($decodedResponse['session']['sid']) && $decodedResponse['session']['valid']) {
            $sid = $decodedResponse['session']['sid'];
            $this->SetValue('SID', $sid);
            $this->SendDebug(__FUNCTION__, 'Authentication successful. SID: ' . $sid, 0);
            return true;
        }

        $this->SendDebug(__FUNCTION__, 'Authentication failed: Invalid response.', 0);
        echo 'Authentication failed: Invalid response.';
        return false;
    }

    private function request(string $endpoint, string $sid)
    {
        $url = 'https://' . $this->ReadPropertyString('Host') . ':' . $this->ReadPropertyInteger('Port') . '/api/' . $endpoint . '?sid=' . urlencode($sid);

        $this->SendDebug(__FUNCTION__ . ' URL', $url, 0);

        $options = [
            'http' => [
                'method'  => 'GET',
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