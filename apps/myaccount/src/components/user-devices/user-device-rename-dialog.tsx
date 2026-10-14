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

import Button from "@oxygen-ui/react/Button";
import Dialog from "@oxygen-ui/react/Dialog";
import DialogActions from "@oxygen-ui/react/DialogActions";
import DialogContent from "@oxygen-ui/react/DialogContent";
import DialogTitle from "@oxygen-ui/react/DialogTitle";
import { IdentifiableComponentInterface } from "@wso2is/core/models";
import { FinalForm, FinalFormField, FormRenderProps, FormValue, TextFieldAdapter } from "@wso2is/forms";
import React, { FunctionComponent, ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { UserDeviceInterface } from "../../models";

/**
 * Maximum length of a device name accepted by the API.
 */
export const DEVICE_NAME_MAX_LENGTH: number = 255;

interface UserDeviceRenameDialogPropsInterface extends IdentifiableComponentInterface {
    device: UserDeviceInterface | null;
    isSubmitting: boolean;
    onClose: () => void;
    onSubmit: (deviceName: string) => void;
}

interface RenameFormValuesInterface {
    deviceName: string;
}

/**
 * Dialog to rename a device registered to the user.
 *
 * @param props - Props injected to the component.
 * @returns Rename dialog.
 */
export const UserDeviceRenameDialog: FunctionComponent<UserDeviceRenameDialogPropsInterface> = (
    props: UserDeviceRenameDialogPropsInterface
): ReactElement => {

    const {
        device,
        isSubmitting,
        onClose,
        onSubmit,
        ["data-componentid"]: componentId = "user-device-rename-dialog"
    } = props;

    const { t } = useTranslation();

    const validateDeviceName = (value: FormValue): string | undefined => {
        const deviceName: string = value?.toString().trim() ?? "";

        if (!deviceName) {
            return t("myAccount:components.userDevices.forms.rename.inputs.deviceName.validations.empty");
        }
        if (deviceName.length > DEVICE_NAME_MAX_LENGTH) {
            return t("myAccount:components.userDevices.forms.rename.inputs.deviceName.validations.maxLength",
                { length: DEVICE_NAME_MAX_LENGTH });
        }

        return undefined;
    };

    return (
        <Dialog
            open={ Boolean(device) }
            onClose={ onClose }
            fullWidth={ true }
            maxWidth="xs"
            data-componentid={ componentId }
        >
            <FinalForm
                onSubmit={ (values: RenameFormValuesInterface) => onSubmit(values.deviceName.trim()) }
                initialValues={ { deviceName: device?.deviceName } }
                render={ ({ handleSubmit }: FormRenderProps) => (
                    <form onSubmit={ handleSubmit }>
                        <DialogTitle>
                            { t("myAccount:components.userDevices.forms.rename.heading") }
                        </DialogTitle>
                        <DialogContent>
                            <FinalFormField
                                autoFocus={ true }
                                component={ TextFieldAdapter }
                                data-componentid={ `${ componentId }-device-name-field` }
                                label={ t("myAccount:components.userDevices.forms.rename.inputs.deviceName.label") }
                                name="deviceName"
                                placeholder={
                                    t("myAccount:components.userDevices.forms.rename.inputs.deviceName.placeholder")
                                }
                                required={ true }
                                type="text"
                                validate={ validateDeviceName }
                            />
                        </DialogContent>
                        <DialogActions>
                            <Button
                                onClick={ onClose }
                                disabled={ isSubmitting }
                                data-componentid={ `${ componentId }-cancel-button` }
                            >
                                { t("common:cancel") }
                            </Button>
                            <Button
                                type="submit"
                                variant="contained"
                                disabled={ isSubmitting }
                                data-componentid={ `${ componentId }-submit-button` }
                            >
                                { t("common:update") }
                            </Button>
                        </DialogActions>
                    </form>
                ) }
            />
        </Dialog>
    );
};
