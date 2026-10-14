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

import Alert from "@oxygen-ui/react/Alert";
import Autocomplete, { AutocompleteRenderInputParams } from "@oxygen-ui/react/Autocomplete";
import CircularProgress from "@oxygen-ui/react/CircularProgress";
import Stack from "@oxygen-ui/react/Stack";
import TextField from "@oxygen-ui/react/TextField";
import Typography from "@oxygen-ui/react/Typography";
import { useGetDevicePolicies } from "@wso2is/admin.device-policies.v1/hooks/use-get-device-policies";
import { PolicyListItemInterface } from "@wso2is/admin.device-policies.v1/models/device-policy";
import { IdentifiableComponentInterface } from "@wso2is/core/models";
import React, { FunctionComponent, ReactElement, SyntheticEvent, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { CommonResourcePropertiesPropsInterface } from "../resource-properties";

/**
 * Props interface of {@link DeviceRegistrationProperties}
 */
type DeviceRegistrationPropertiesPropsInterface = CommonResourcePropertiesPropsInterface &
    IdentifiableComponentInterface;

/**
 * Property panel for the DeviceRegistrationExecutor step.
 * Lets the user pick a device assurance policy (or none) to attach to the executor.
 *
 * @param props - Props injected to the component.
 * @returns DeviceRegistrationProperties component.
 */
const DeviceRegistrationProperties: FunctionComponent<DeviceRegistrationPropertiesPropsInterface> = ({
    resource,
    onChange,
    "data-componentid": componentId = "device-registration-properties"
}: DeviceRegistrationPropertiesPropsInterface): ReactElement => {
    const { t } = useTranslation();

    const { data: policyListResponse, isLoading, error } = useGetDevicePolicies();

    const noPolicyOption: PolicyListItemInterface = useMemo(
        (): PolicyListItemInterface => ({
            id: "",
            name: t("flows:core.executions.deviceRegistration.noPolicy")
        }),
        [ t ]
    );

    const options: PolicyListItemInterface[] = useMemo((): PolicyListItemInterface[] => {
        return [ noPolicyOption, ...(policyListResponse?.policies ?? []) ];
    }, [ noPolicyOption, policyListResponse ]);

    const currentPolicyName: string = resource?.data?.action?.executor?.meta?.policyName ?? "";

    const selectedPolicy: PolicyListItemInterface = useMemo(
        (): PolicyListItemInterface =>
            options.find((option: PolicyListItemInterface): boolean => option.name === currentPolicyName)
            ?? noPolicyOption,
        [ options, currentPolicyName, noPolicyOption ]
    );

    const handleChange = (_event: SyntheticEvent, value: PolicyListItemInterface): void => {
        onChange(
            "action.executor.meta.policyName",
            value?.id ? value.name : "",
            resource
        );
    };

    if (error) {
        return (
            <Alert severity="error" data-componentid={ `${ componentId }-error` }>
                { t("flows:core.executions.deviceRegistration.policyFetchError") }
            </Alert>
        );
    }

    return (
        <Stack gap={ 2 } data-componentid={ componentId }>
            <Typography variant="body2">
                { t("flows:core.executions.deviceRegistration.description") }
            </Typography>
            <Autocomplete
                disablePortal
                key={ resource.id }
                options={ options }
                loading={ isLoading }
                getOptionLabel={ (option: PolicyListItemInterface): string => option.name }
                isOptionEqualToValue={ (
                    option: PolicyListItemInterface,
                    value: PolicyListItemInterface
                ): boolean => option.id === value.id }
                value={ selectedPolicy }
                onChange={ handleChange }
                renderInput={ (params: AutocompleteRenderInputParams): ReactElement => (
                    <TextField
                        { ...params }
                        label={ t("flows:core.executions.deviceRegistration.policyLabel") }
                        placeholder={ t("flows:core.executions.deviceRegistration.policyPlaceholder") }
                        InputProps={ {
                            ...params.InputProps,
                            endAdornment: (
                                <>
                                    { isLoading && <CircularProgress size={ 16 } /> }
                                    { params.InputProps.endAdornment }
                                </>
                            )
                        } }
                        data-componentid={ `${ componentId }-policy-input` }
                    />
                ) }
                data-componentid={ `${ componentId }-policy-select` }
            />
        </Stack>
    );
};

export default DeviceRegistrationProperties;
