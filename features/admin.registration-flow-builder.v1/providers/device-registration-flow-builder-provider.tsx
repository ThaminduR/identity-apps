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

import updateFlowConfig from "@wso2is/admin.flow-builder-core.v1/api/update-flow-config";
import { ValidationConfig } from "@wso2is/admin.flow-builder-core.v1/context/validation-context";
import useAuthenticationFlowBuilderCore from
    "@wso2is/admin.flow-builder-core.v1/hooks/use-authentication-flow-builder-core-context";
import { Payload } from "@wso2is/admin.flow-builder-core.v1/models/api";
import AuthenticationFlowBuilderCoreProvider
    from "@wso2is/admin.flow-builder-core.v1/providers/authentication-flow-builder-core-provider";
import { FlowTypes } from "@wso2is/admin.flows.v1/models/flows";
import { PreviewScreenType } from "@wso2is/common.branding.v1/models/branding-preferences";
import { AlertLevels } from "@wso2is/core/models";
import { addAlert } from "@wso2is/core/store";
import { ReactFlowJsonObject, useReactFlow } from "@xyflow/react";
import isEmpty from "lodash-es/isEmpty";
import React, { FunctionComponent, PropsWithChildren, ReactElement, useState } from "react";
import { useTranslation } from "react-i18next";
import { useDispatch } from "react-redux";
import { Dispatch } from "redux";
import configureRegistrationFlow from "../api/configure-registration-flow";
import useGetSupportedProfileAttributes from "../api/use-get-supported-profile-attributes";
import ResourceProperties from "../components/resource-property-panel/resource-properties";
import ElementFactory from "../components/resources/elements/element-factory";
import RegistrationFlowBuilderContext from "../context/registration-flow-builder-context";
import { Attribute } from "../models/attributes";
import transformFlow from "../utils/transform-flow";

/**
 * Props interface of {@link DeviceRegistrationFlowBuilderProvider}
 */
type DeviceRegistrationFlowBuilderProviderPropsInterface = PropsWithChildren<unknown>;

const DEVICE_REGISTRATION_SCREEN_TYPES: PreviewScreenType[] = [
    PreviewScreenType.SIGN_UP,
    PreviewScreenType.COMMON,
    PreviewScreenType.EMAIL_LINK_EXPIRY,
    PreviewScreenType.EMAIL_OTP,
    PreviewScreenType.SMS_OTP
];

// A device registration step must be preceded by an Email OTP or SMS OTP step.
const DEVICE_REGISTRATION_VALIDATION_CONFIG: ValidationConfig = {
    isDeviceRegistrationFactorValidationEnabled: true
};

/**
 * Provides the device registration flow builder context to its children.
 *
 * @param props - Props injected to the component.
 * @returns The DeviceRegistrationFlowBuilderProvider component.
 */
const DeviceRegistrationFlowBuilderProvider: FunctionComponent<DeviceRegistrationFlowBuilderProviderPropsInterface> = ({
    children
}: DeviceRegistrationFlowBuilderProviderPropsInterface): ReactElement => (
    <AuthenticationFlowBuilderCoreProvider
        ElementFactory={ ElementFactory }
        ResourceProperties={ ResourceProperties }
        flowType={ FlowTypes.DEVICE_REGISTRATION }
        screenTypes={ DEVICE_REGISTRATION_SCREEN_TYPES }
        validationConfig={ DEVICE_REGISTRATION_VALIDATION_CONFIG }
    >
        <FlowContextWrapper>{ children }</FlowContextWrapper>
    </AuthenticationFlowBuilderCoreProvider>
);

/**
 * Wraps the flow context and provides the publish handler and attribute state.
 *
 * @param props - Props injected to the component.
 * @returns The FlowContextWrapper component.
 */
const FlowContextWrapper: FunctionComponent<DeviceRegistrationFlowBuilderProviderPropsInterface> = ({
    children
}: DeviceRegistrationFlowBuilderProviderPropsInterface): ReactElement => {
    const dispatch: Dispatch = useDispatch();
    const { t } = useTranslation();

    const { toObject } = useReactFlow();
    const { data: supportedAttributes } = useGetSupportedProfileAttributes();
    const { flowCompletionConfigs } = useAuthenticationFlowBuilderCore();

    const [ selectedAttributes, setSelectedAttributes ] = useState<{ [key: string]: Attribute[] }>({});
    const [ isPublishing, setIsPublishing ] = useState<boolean>(false);

    const handlePublish: () => Promise<boolean> = async (): Promise<boolean> => {
        setIsPublishing(true);

        const flow: ReactFlowJsonObject = toObject();

        if (!isEmpty(flowCompletionConfigs)) {
            try {
                await updateFlowConfig({
                    flowCompletionConfigs,
                    flowType: FlowTypes.DEVICE_REGISTRATION
                });
            } catch {
                dispatch(
                    addAlert({
                        description: t("flows:core.notifications.updateFlowConfig.genericError.description"),
                        level: AlertLevels.ERROR,
                        message: t("flows:core.notifications.updateFlowConfig.genericError.message")
                    })
                );
            }
        }

        try {
            const deviceRegistrationFlow: Payload = {
                ...transformFlow(flow),
                flowType: FlowTypes.DEVICE_REGISTRATION
            };

            await configureRegistrationFlow(deviceRegistrationFlow);

            dispatch(
                addAlert({
                    description: t(
                        "flows:deviceRegistrationFlow.notifications.updateDeviceRegistrationFlow.success.description"
                    ),
                    level: AlertLevels.SUCCESS,
                    message: t(
                        "flows:deviceRegistrationFlow.notifications.updateDeviceRegistrationFlow.success.message"
                    )
                })
            );

            return true;
        } catch {
            dispatch(
                addAlert({
                    description: t(
                        "flows:deviceRegistrationFlow.notifications.updateDeviceRegistrationFlow.genericError"
                            + ".description"
                    ),
                    level: AlertLevels.ERROR,
                    message: t(
                        "flows:deviceRegistrationFlow.notifications.updateDeviceRegistrationFlow.genericError.message"
                    )
                })
            );

            return false;
        } finally {
            setIsPublishing(false);
        }
    };

    return (
        <RegistrationFlowBuilderContext.Provider
            value={ {
                isPublishing,
                onPublish: handlePublish,
                selectedAttributes,
                setSelectedAttributes,
                supportedAttributes
            } }
        >
            { children }
        </RegistrationFlowBuilderContext.Provider>
    );
};

export default DeviceRegistrationFlowBuilderProvider;
