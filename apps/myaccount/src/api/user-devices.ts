/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import { AsgardeoSPAClient, HttpError, HttpInstance, HttpRequestConfig, HttpResponse } from "@asgardeo/auth-react";
import {
    HttpMethods,
    UserDeviceInterface,
    UserDeviceListInterface,
    UserDevicePatchRequestInterface
} from "../models";
import { store } from "../store";

const httpClient: HttpInstance = AsgardeoSPAClient.getInstance().httpRequest.bind(AsgardeoSPAClient.getInstance());

/**
 * Maximum number of devices the API returns in a single page.
 */
const USER_DEVICES_PAGE_LIMIT: number = 100;

/**
 * Fetches the devices registered to the authenticated user.
 *
 * @returns A promise containing the device list.
 */
export const getUserDevices = (): Promise<UserDeviceListInterface> => {
    const requestConfig: HttpRequestConfig = {
        headers: {
            Accept: "application/json"
        },
        method: HttpMethods.GET,
        params: {
            limit: USER_DEVICES_PAGE_LIMIT
        },
        url: store.getState().config.endpoints.devices
    };

    return httpClient(requestConfig)
        .then((response: HttpResponse<UserDeviceListInterface>) => {
            return response.data;
        })
        .catch((error: HttpError) => {
            return Promise.reject(error);
        });
};

/**
 * Renames, activates or deactivates a device registered to the authenticated user.
 *
 * @param id - Device ID.
 * @param patch - Properties to update.
 * @returns A promise containing the updated device.
 */
export const updateUserDevice = (
    id: string,
    patch: UserDevicePatchRequestInterface
): Promise<UserDeviceInterface> => {
    const requestConfig: HttpRequestConfig = {
        data: patch,
        headers: {
            Accept: "application/json",
            "Content-Type": "application/json"
        },
        method: HttpMethods.PATCH,
        url: `${ store.getState().config.endpoints.devices }/${ id }`
    };

    return httpClient(requestConfig)
        .then((response: HttpResponse<UserDeviceInterface>) => {
            return response.data;
        })
        .catch((error: HttpError) => {
            return Promise.reject(error);
        });
};

/**
 * Removes a device registered to the authenticated user.
 *
 * @param id - Device ID.
 * @returns A promise that resolves once the device is removed.
 */
export const deleteUserDevice = (id: string): Promise<void> => {
    const requestConfig: HttpRequestConfig = {
        headers: {
            Accept: "application/json"
        },
        method: HttpMethods.DELETE,
        url: `${ store.getState().config.endpoints.devices }/${ id }`
    };

    return httpClient(requestConfig)
        .then(() => {
            return;
        })
        .catch((error: HttpError) => {
            return Promise.reject(error);
        });
};
