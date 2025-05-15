<?php

declare(strict_types=1);

class PiHole extends IPSModule
{
    public function Create()
    {
        parent::Create();
        $this->RegisterPropertyString('Host', '');
        $this->RegisterPropertyInteger('Port', 80);
        $this->RegisterPropertyString('ApiToken', '');
        $this->RegisterPropertyInteger('UpdateTimerInterval', 20);

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

        if (!IPS_VariableProfileExists('PiHole.Percent')) {
            IPS_CreateVariableProfile('PiHole.Percent', 1);
            IPS_SetVariableProfileText('PiHole.Percent', '', ' %');
        }
        $this->RegisterVariableInteger('PihAdsPrecentageToday', $this->Translate('Ads Percentage Today'), 'PiHole.Percent', 9);
        $this->RegisterTimer('Pih_updateStatus', 0, 'Pih_updateStatus($_IPS[\'TARGET\']);');
    }

    public function ApplyChanges()
    {
        parent::ApplyChanges();
        if ($this->ReadPropertyString('Host') != '') {
            $this->SetTimerInterval('Pih_updateStatus', $this->ReadPropertyInteger('UpdateTimerInterval') * 1000);
        } else {
            $this->SetTimerInterval('Pih_updateStatus', 0);
        }
    }

    public function updateStatus()
    {
        $data = $this->getSummaryData();
        if (!$data) {
            $this->SendDebug(__FUNCTION__, 'Problem beim API-Request!', 0);
            return;
        }
        // Update Variablen
        $this->SetValue('PihBlockedDomains', $data['domains_being_blocked'] ?? 0);
        $this->SetValue('PihDNSQueriesToday', $data['dns_queries_today'] ?? 0);
        $this->SetValue('PihAdsBlockedToday', $data['ads_blocked_today'] ?? 0);
        $this->SetValue('PihAdsPrecentageToday', intval($data['ads_percentage_today'] ?? 0));
        $this->SetValue('PihQueriesCached', $data['queries_cached'] ?? 0);
        $this->SetValue('PihDNSQueriesAllTypes', $data['dns_queries_all_types'] ?? 0);
        $this->SetValue('PihGravityLastUpdated', $data['gravity_last_updated']['absolute'] ?? 0);
        $this->SetValue('PihStatus', $this->getPiholeStatus());
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

    private function getSummaryData(): ?array
    {
        return $this->requestApi('/admin/api/summary');
    }

    private function getPiholeStatus(): bool
    {
        $data = $this->requestApi('/admin/api/status');
        if ($data && isset($data['status'])) {
            return strtolower($data['status']) === 'enabled';
        }
        return false;
    }

    public function setActive(bool $active)
    {
        if ($active) {
            $res = $this->requestApi('/admin/api/enable', 'POST');
        } else {
            $duration = $this->GetValue('PihDisableTime');
            $res = $this->requestApi('/admin/api/disable', 'POST', ($duration > 0) ? ['duration' => $duration] : []);
        }
        // Status aktualisieren
        IPS_Sleep(500);
        $this->SetValue('PihStatus', $this->getPiholeStatus());
    }

    /**
     * Generische Pi-hole-API-Anfrage (FTL API)
     * @param string $endpoint z.B. '/admin/api/summary'
     * @param string $method GET/POST
     * @param array $postData optionales POST-Array
     * @return array|null
     */
    private function requestApi(string $endpoint, string $method = 'GET', array $postData = null): ?array
    {
        $host = $this->ReadPropertyString('Host');
        $port = $this->ReadPropertyInteger('Port');
        $token = $this->ReadPropertyString('ApiToken');
        $url = "http://$host:$port$endpoint";
        if (!empty($token)) {
            $url .= (strpos($url, '?') === false ? '?' : '&') . "token=" . urlencode($token);
        }

        $headers = [
            'Content-Type: application/json'
        ];
        $opts = [
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", $headers),
                'ignore_errors' => true
            ]
        ];

        if ($method === 'POST' && $postData !== null) {
            $opts['http']['content'] = json_encode($postData);
        }

        $context = stream_context_create($opts);
        $result = @file_get_contents($url, false, $context);
        if ($result === false) {
            $this->SendDebug(__FUNCTION__, 'Fehler beim Request: ' . $url, 0);
            return null;
        }
        $json = json_decode($result, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->SendDebug(__FUNCTION__, 'Ungültiges JSON von ' . $url, 0);
            return null;
        }
        return $json;
    }
}