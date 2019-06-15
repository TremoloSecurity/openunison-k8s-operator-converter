/*
Copyright 2019 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package com.tremolosecurity.openunison;

import java.security.Key;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;

/**
 * KeyPair
 */
public class KeyPair {

    public X509Certificate cert;
    public Key key;

    public KeyPair(X509Certificate cert,Key key) {
        this.cert = cert;
        this.key = key;
    }
}