#!/usr/bin/php -q
<?php
        $filters = array(
                '/user splynx logged/',
                '/^(?=.*\boffering\b)(?=.*\blease\b)(?=.*\bwithout\b)(?=.*\bsuccess\b).*$/',
                '/Clean php session files/',
        );

        require_once("/opt/observium/config.php");

        function obsmatch($hostname) {
                global $config;
                $db = new mysqli($config["db_host"], $config["db_user"], $config["db_pass"], $config["db_name"]) or die($db->error);
                if (strstr($hostname, ".")) {
                        $x = explode(".", $hostname);
                        $hostname = $x[0];
                }
                $hostname = $db->real_escape_string(trim($hostname));
                $qid = $db->query("SELECT * FROM `devices` WHERE `hostname` LIKE '{$hostname}%' OR `sysName` LIKE '{$hostname}%';");
                $row = @$qid->fetch_assoc();
                $db->close();
                if (is_array($row)) { return $row["device_id"]; }
                else { return false; }
        }

        function logToObs($log) {
                global $config;
                $devid = obsmatch($log["device"]);
                if ($devid !== false) {
                        $db = new mysqli($config["db_host"], $config["db_user"], $config["db_pass"], $config["db_name"]);
                        foreach ($log as $k => $v) {
                                $log[$k] = $db->real_escape_string($v);
                        }
                        $q = "INSERT INTO `syslog` (`device_id`, `host`, `facility`, `priority`, `level`, `tag`, `timestamp`, `program`, `msg`, `seq`) VALUES ($devid, '{$log["remote_ip"]}', '{$log["facility"]}', {$log["priority"]}, {$log["level"]}, '', NOW(), '{$log["program"]}', '{$log["message"]}', 0);";
                        $db->query($q);
                        $db->close();
                }
        }

        if (!($sock = socket_create(AF_INET, SOCK_DGRAM, 0))) {
                $errorcode = socket_last_error();
                $errormsg = socket_strerror($errorcode);
                die("Couldn't create socket: [$errorcode] $errormsg \n");
        }

        if (!socket_bind($sock, "0.0.0.0" , 5144)) {
                $errorcode = socket_last_error();
                $errormsg = socket_strerror($errorcode);
                die("Could not bind socket : [$errorcode] $errormsg \n");
        }

        function getFacility($level) {
                if (($level >= 0) && ($level <= 7)) { return "kernel"; }
                if (($level >= 8) && ($level <= 15)) { return "user"; }
                if (($level >= 16) && ($level <= 23)) { return "mail"; }
                if (($level >= 24) && ($level <= 31)) { return "system"; }
                if (($level >= 32) && ($level <= 39)) { return "security"; }
                if (($level >= 40) && ($level <= 47)) { return "syslog"; }
                if (($level >= 48) && ($level <= 55)) { return "lpd"; }
                if (($level >= 56) && ($level <= 63)) { return "nntp"; }
                if (($level >= 64) && ($level <= 71)) { return "uucp"; }
                if (($level >= 72) && ($level <= 79)) { return "time"; }
                if (($level >= 80) && ($level <= 87)) { return "security"; }
                if (($level >= 88) && ($level <= 95)) { return "ftpd"; }
                if (($level >= 96) && ($level <= 103)) { return "ntpd"; }
                if (($level >= 104) && ($level <= 111)) { return "logaudit"; }
                if (($level >= 112) && ($level <= 119)) { return "logalert"; }
                if (($level >= 120) && ($level <= 127)) { return "clock"; }
                if (($level >= 128) && ($level <= 135)) { return "local0"; }
                if (($level >= 136) && ($level <= 143)) { return "local1"; }
                if (($level >= 144) && ($level <= 151)) { return "local2"; }
                if (($level >= 152) && ($level <= 169)) { return "local3"; }
                if (($level >= 160) && ($level <= 167)) { return "local4"; }
                if (($level >= 168) && ($level <= 175)) { return "local5"; }
                if (($level >= 176) && ($level <= 183)) { return "local6"; }
                if (($level >= 184) && ($level <= 191)) { return "local7"; }
        }

        $priorities = array("emergency" => array(), "alert" => array(), "critical" => array(), "error" => array(), "warning" => array(), "notice" => array(), "info" => array(), "debug" => array());
        $prev = 0;
        for ($i = 0; $i < 24; $i++) {
                $priorities["emergency"][] = $prev++;
                $priorities["alert"][] = $prev++;
                $priorities["critical"][] = $prev++;
                $priorities["error"][] = $prev++;
                $priorities["warning"][] = $prev++;
                $priorities["notice"][] = $prev++;
                $priorities["info"][] = $prev++;
                $priorities["debug"][] = $prev++;
        }

        function getPriority($level) {
                global $priorities;
                foreach ($priorities as $k => $v) {
                        foreach ($v as $l) {
                                if ($l == $level) { return $k; }
                        }
                }
                return "info";
        }

        while(1) {
                $r = socket_recvfrom($sock, $buf, 512, 0, $remote_ip, $remote_port);
                $x = explode(" ", $buf);
                $junk = $x[0];
                $junk = explode(">", $junk);
                $priority = str_replace("<", "", $junk[0]);
                $timestamp = "{$junk[1]} {$x[1]} {$x[2]}";
                $device = $x[3];
                if (strstr($x[4], ":")) {
                        $program = str_replace(":", "", $x[4]);
                        $message = implode(" ", array_slice($x, 5));
                }
                else {
                        $message = implode(" ", array_slice($x, 4));
                        if (strstr($message, "telnet")) { $program = "telnet"; }
                        elseif (strstr($message, "winbox")) { $program = "winbox"; }
                        else { $program = "syslog"; }
                }
                $dt = new DateTime($timestamp);
                $log = array(
                                "remote_ip" => $remote_ip,
                                "remote_port" => $remote_port,
                                "priority" => $priority,
                                "facility" => getFacility($priority),
                                "level" => floor($priority / 24),
                                "level_name" => getPriority($priority),
                                "timestamp" => $timestamp,
                                "year" => $dt->format("Y"),
                                "month" => $dt->format("M"),
                                "day" => $dt->format("d"),
                                "hours" => $dt->format("H"),
                                "mins" => $dt->format("i"),
                                "secs" => $dt->format("s"),
                                "device" => $device,
                                "message" => trim($message),
                                "program" => $program
                );

                $drop = false;
                foreach ($filters as $f) {
                        if (preg_match($f, $log["message"])) { $drop = true; }
                }

                if ($drop) {
                        //debug: print "Dropping message: {$log["message"]}\n";
                        //debug: file_put_contents("/var/log/joshlog.log", "Dropped message: {$log["message"]}\n", FILE_APPEND);
                }
                else {
                        file_put_contents("/var/log/joshlog.log", json_encode($log)."\n", FILE_APPEND);
                        logToObs($log);
                }
        }

        socket_close($sock);

?>
