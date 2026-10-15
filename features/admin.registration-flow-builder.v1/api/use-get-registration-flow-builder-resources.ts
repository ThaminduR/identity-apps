/**
 * Copyright (c) 2025-2026, WSO2 LLC. (https://www.wso2.com).
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

import { FeatureAccessConfigInterface } from "@wso2is/access-control";
import { RequestErrorInterface, RequestResultInterface } from "@wso2is/admin.core.v1/hooks/use-request";
import { AppState } from "@wso2is/admin.core.v1/store";
import FeatureFlagConstants from "@wso2is/admin.feature-gate.v1/constants/feature-flag-constants";
import useGetExtensionExecutorSteps
    from "@wso2is/admin.flow-builder-core.v1/api/use-get-extension-executor-steps";
import useGetFlowBuilderCoreResources from "@wso2is/admin.flow-builder-core.v1/api/use-get-flow-builder-core-resources";
import { Resources } from "@wso2is/admin.flow-builder-core.v1/models/resources";
import { ExecutionTypes, Step } from "@wso2is/admin.flow-builder-core.v1/models/steps";
import { Template, TemplateTypes } from "@wso2is/admin.flow-builder-core.v1/models/templates";
import { WidgetTypes } from "@wso2is/admin.flow-builder-core.v1/models/widget";
import { FlowTypes } from "@wso2is/admin.flows.v1/models/flows";
import { useMemo } from "react";
import { useSelector } from "react-redux";
import deviceRegistrationTemplates from "../data/device-registration-templates.json";
import deviceRegistrationWidgets from "../data/device-registration-widgets.json";
import elements from "../data/elements.json";
import steps from "../data/steps.json";
import templates from "../data/templates.json";
import widgets from "../data/widgets.json";

/**
 * Labels of the core steps offered on the resource panel of the device registration flow builder.
 */
const DEVICE_REGISTRATION_PANEL_CORE_STEP_LABELS: Set<string> = new Set<string>([
    "Blank View",
    "Email OTP View",
    "SMS OTP View"
]);

/**
 * Hides a step from the resource panel unless it is allowed in the device registration flow builder.
 *
 * @param step - Step to process.
 * @param isAllowed - Whether the step should remain visible on the resource panel.
 * @returns Step with the resource panel visibility resolved.
 */
const resolveDeviceRegistrationPanelStep = (step: Step, isAllowed: boolean): Step => ({
    ...step,
    display: {
        ...step?.display,
        showOnResourcePanel: isAllowed && (step?.display?.showOnResourcePanel ?? false)
    }
});

/**
 * Hook to get the resources supported by the registration flow builder.
 * This hook will aggregate the core resources and the registration specific resources.
 * For the device registration flow, the resource panel is limited to the device registration step and the
 * Email OTP and SMS OTP factors.
 *
 * @param flowType - Flow type the resources are resolved for.
 * @param _shouldFetch - Should fetch the data.
 * @returns SWR response object containing the data, error, isLoading, isValidating, mutate.
 */
const useGetRegistrationFlowBuilderResources = <Data = Resources, Error = RequestErrorInterface>(
    flowType: FlowTypes = FlowTypes.REGISTRATION,
    _shouldFetch: boolean = true
): RequestResultInterface<Data, Error> => {
    const { data: coreResources } = useGetFlowBuilderCoreResources();

    // Executors contributed by extensions deployed on the server. Appended to the palette at runtime.
    const extensionExecutorSteps: Step[] = useGetExtensionExecutorSteps(flowType);

    const aiFeature: FeatureAccessConfigInterface = useSelector(
        (state: AppState) => state.config.ui.features?.ai
    );

    const presentationDefinitionsFeature: FeatureAccessConfigInterface = useSelector(
        (state: AppState) => state.config.ui.features?.presentationDefinitions
    );

    const data: unknown = useMemo(() => {
        if (flowType === FlowTypes.DEVICE_REGISTRATION) {
            return {
                ...coreResources,
                steps: [
                    ...(coreResources?.steps ?? []).map((step: Step) => resolveDeviceRegistrationPanelStep(
                        step,
                        DEVICE_REGISTRATION_PANEL_CORE_STEP_LABELS.has(step?.display?.label)
                    )),
                    ...(steps as Step[]).map((step: Step) => resolveDeviceRegistrationPanelStep(
                        step,
                        step?.data?.action?.executor?.name === ExecutionTypes.DeviceRegistration
                    )),
                    ...extensionExecutorSteps
                ],
                templates: deviceRegistrationTemplates,
                widgets: deviceRegistrationWidgets
            };
        }

        const isAiFeatureDisabled: boolean = !aiFeature?.enabled || aiFeature?.disabledFeatures?.includes(
            FeatureFlagConstants.FEATURE_FLAG_KEY_MAP.AI_FLOWS_TYPES_REGISTRATION);

        const isOpenID4VPDisabled: boolean = !presentationDefinitionsFeature?.enabled ||
            presentationDefinitionsFeature?.disabledFeatures?.includes(
                FeatureFlagConstants.FEATURE_FLAG_KEY_MAP.PRESENTATION_DEFINITIONS_FLOWS_TYPES_REGISTRATION
            );

        const filteredTemplates: Template[] = (templates as Template[]).filter((template: Template) => {
            return (!isAiFeatureDisabled || template?.type !== TemplateTypes.GeneratedWithAI) &&
                (!isOpenID4VPDisabled || template?.type !== TemplateTypes.BasicWallet);
        });

        const filteredWidgets: any[] = (widgets as any[]).filter((widget: any) => {
            return !isOpenID4VPDisabled || widget?.type !== WidgetTypes.DigitalWalletFederation;
        });

        return {
            ...coreResources,
            elements: [
                ...coreResources?.elements,
                ...elements
            ],
            steps: [
                ...coreResources?.steps,
                ...steps,
                ...extensionExecutorSteps
            ],
            templates: [
                ...coreResources?.templates,
                ...filteredTemplates
            ],
            widgets: [
                ...coreResources?.widgets,
                ...filteredWidgets
            ]
        };
    }, [ coreResources, aiFeature, presentationDefinitionsFeature, extensionExecutorSteps, flowType ]);

    return {
        data: data as Data,
        error: null,
        isLoading: false,
        isValidating: false,
        mutate: () => null
    };
};

export default useGetRegistrationFlowBuilderResources;
