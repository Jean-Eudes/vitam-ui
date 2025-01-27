/*
 * Copyright French Prime minister Office/SGMAP/DINSIC/Vitam Program (2019-2020)
 * and the signatories of the "VITAM - Accord du Contributeur" agreement.
 *
 * contact@programmevitam.fr
 *
 * This software is a computer program whose purpose is to implement
 * implement a digital archiving front-office system for the secure and
 * efficient high volumetry VITAM solution.
 *
 * This software is governed by the CeCILL-C license under French law and
 * abiding by the rules of distribution of free software.  You can  use,
 * modify and/ or redistribute the software under the terms of the CeCILL-C
 * license as circulated by CEA, CNRS and INRIA at the following URL
 * "http://www.cecill.info".
 *
 * As a counterpart to the access to the source code and  rights to copy,
 * modify and redistribute granted by the license, users are provided only
 * with a limited warranty  and the software's author,  the holder of the
 * economic rights,  and the successive licensors  have only  limited
 * liability.
 *
 * In this respect, the user's attention is drawn to the risks associated
 * with loading,  using,  modifying and/or developing or reproducing the
 * software by the user in light of its specific status of free software,
 * that may mean  that it is complicated to manipulate,  and  that  also
 * therefore means  that it is reserved for developers  and  experienced
 * professionals having in-depth computer knowledge. Users are therefore
 * encouraged to load and test the software's suitability as regards their
 * requirements in conditions enabling the security of their systems and/or
 * data to be ensured and,  more generally, to use and operate it in the
 * same conditions as regards security.
 *
 * The fact that you are presently reading this means that you have had
 * knowledge of the CeCILL-C license and that you accept its terms.
 */
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';

import { BaseHttpClient, BASE_URL, IdentityProvider } from 'ui-frontend-common';

@Injectable({
  providedIn: 'root',
})
export class ProviderApiService extends BaseHttpClient<IdentityProvider> {
  constructor(http: HttpClient, @Inject(BASE_URL) baseUrl: string) {
    super(http, baseUrl + '/providers');
  }

  create(identityProvider: IdentityProvider, headers?: HttpHeaders): Observable<IdentityProvider> {
    const formData = new FormData();
    if (identityProvider.keystore && identityProvider.idpMetadata) {
      formData.append('keystore', identityProvider.keystore, identityProvider.keystore.name);
      formData.append('idpMetadata', identityProvider.idpMetadata, identityProvider.idpMetadata.name);
    }
    formData.append(
      'provider',
      JSON.stringify({
        protocoleType: identityProvider.protocoleType,
        customerId: identityProvider.customerId,
        name: identityProvider.name,
        internal: identityProvider.internal,
        keystorePassword: identityProvider.keystorePassword,
        patterns: identityProvider.patterns,
        enabled: identityProvider.enabled,
        mailAttribute: identityProvider.mailAttribute,
        identifierAttribute: identityProvider.identifierAttribute,
        authnRequestBinding: identityProvider.authnRequestBinding,
        autoProvisioningEnabled: identityProvider.autoProvisioningEnabled,
        clientId: identityProvider.clientId,
        clientSecret: identityProvider.clientSecret,
        discoveryUrl: identityProvider.discoveryUrl,
        scope: identityProvider.scope,
        preferredJwsAlgorithm: identityProvider.preferredJwsAlgorithm,
        customParams: identityProvider.customParams,
        useState: identityProvider.useState,
        useNonce: identityProvider.useNonce,
        usePkce: identityProvider.usePkce,
      })
    );

    return this.http.post<IdentityProvider>(this.apiUrl, formData, { headers });
  }


  patch(partialIDP: { id: string; [key: string]: any }, headers?: HttpHeaders): Observable<IdentityProvider> {
    return super.patch(partialIDP, headers);
  }

  patchProviderIdpMetadata(identityProviderId: string, idpMetadata: File, headers?: HttpHeaders): Observable<IdentityProvider> {
    const formData = new FormData();

    formData.append('idpMetadata', idpMetadata, idpMetadata.name);
    formData.append('provider', JSON.stringify({ id: identityProviderId }));

    return this.http.patch<IdentityProvider>(this.apiUrl + '/' + identityProviderId + '/idpMetadata', formData, { headers });
  }

  patchProviderKeystore(
    identityProviderId: string,
    keystore: File,
    keystorePassword: string,
    headers?: HttpHeaders
  ): Observable<IdentityProvider> {
    const formData = new FormData();

    formData.append('keystore', keystore, keystore.name);
    formData.append('provider', JSON.stringify({ id: identityProviderId, keystorePassword }));

    return this.http.patch<IdentityProvider>(this.apiUrl + '/' + identityProviderId + '/keystore', formData, { headers });
  }

  getAll(params: HttpParams, headers?: HttpHeaders): Observable<IdentityProvider[]> {
    return this.http.get<IdentityProvider[]>(this.apiUrl, { params, headers });
  }

  buildMetadataUrl(identityProviderId: string, tenantIdentifier: string): string {
    return this.apiUrl + `/${identityProviderId}/idpMetadata?tenantId=${tenantIdentifier}`;
  }
}
