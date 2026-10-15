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

import Box from "@oxygen-ui/react/Box";
import Chip from "@oxygen-ui/react/Chip";
import IconButton from "@oxygen-ui/react/IconButton";
import List from "@oxygen-ui/react/List";
import ListItem from "@oxygen-ui/react/ListItem";
import ListItemText from "@oxygen-ui/react/ListItemText";
import Skeleton from "@oxygen-ui/react/Skeleton";
import Tooltip from "@oxygen-ui/react/Tooltip";
import { BanIcon, CheckIcon, PenToSquareIcon, TrashIcon } from "@oxygen-ui/react-icons";
import { Theme, styled } from "@mui/material/styles";
import { HttpErrorResponseDataInterface, IdentifiableComponentInterface } from "@wso2is/core/models";
import { ConfirmationModal } from "@wso2is/react-components";
import { AxiosError } from "axios";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import React, {
    FunctionComponent,
    MutableRefObject,
    ReactElement,
    useCallback,
    useEffect,
    useRef,
    useState
} from "react";
import { useTranslation } from "react-i18next";
import { UserDeviceRenameDialog } from "./user-device-rename-dialog";
import { deleteUserDevice, getUserDevices, updateUserDevice } from "../../api";
import {
    AlertInterface,
    AlertLevels,
    UserDeviceInterface,
    UserDeviceListInterface,
    UserDevicePatchRequestInterface,
    UserDeviceStatus
} from "../../models";
import { SettingsSection } from "../shared";

interface UserDevicesComponentPropsInterface extends IdentifiableComponentInterface {
    onAlertFired: (alert: AlertInterface) => void;
}

dayjs.extend(relativeTime);

type DeviceNotificationKey = "activateDevice" | "deactivateDevice" | "fetchDevices" | "removeDevice" | "renameDevice";

const DeviceActions: typeof Box = styled(Box)(({ theme }: { theme: Theme }) => ({
    alignItems: "center",
    display: "flex",
    gap: theme.spacing(1)
}));

/**
 * Lists the devices registered to the user and lets the user rename, activate, deactivate or remove them.
 * The section is hidden when the user has never registered a device, since devices are registered through
 * application sign-in flows and not from My Account.
 *
 * @param props - Props injected to the component.
 * @returns User devices section.
 */
export const UserDevicesComponent: FunctionComponent<UserDevicesComponentPropsInterface> = (
    props: UserDevicesComponentPropsInterface
): ReactElement => {

    const { onAlertFired, ["data-componentid"]: componentId = "user-devices" } = props;

    const { t } = useTranslation();

    const [ devices, setDevices ] = useState<UserDeviceInterface[]>([]);
    const [ isLoading, setIsLoading ] = useState<boolean>(true);
    const [ hasRegisteredDevices, setHasRegisteredDevices ] = useState<boolean>(false);
    const [ renamingDevice, setRenamingDevice ] = useState<UserDeviceInterface | null>(null);
    const [ removingDevice, setRemovingDevice ] = useState<UserDeviceInterface | null>(null);
    const [ pendingDeviceId, setPendingDeviceId ] = useState<string | null>(null);

    // The parent recreates the alert callback on every render, so keep the latest one in a ref instead of
    // depending on it; otherwise the devices would be re-fetched after every render.
    const onAlertFiredRef: MutableRefObject<(alert: AlertInterface) => void> = useRef(onAlertFired);

    useEffect(() => {
        onAlertFiredRef.current = onAlertFired;
    }, [ onAlertFired ]);

    const fireErrorAlert: (
        notification: DeviceNotificationKey,
        error: AxiosError<HttpErrorResponseDataInterface>
    ) => void = useCallback((
        notification: DeviceNotificationKey,
        error: AxiosError<HttpErrorResponseDataInterface>
    ): void => {
        const description: string | undefined = error?.response?.data?.description;

        if (description) {
            onAlertFiredRef.current({
                description: t(`myAccount:components.userDevices.notifications.${ notification }.error.description`,
                    { description }),
                level: AlertLevels.ERROR,
                message: t(`myAccount:components.userDevices.notifications.${ notification }.error.message`)
            });

            return;
        }

        onAlertFiredRef.current({
            description: t(`myAccount:components.userDevices.notifications.${ notification }.genericError.description`),
            level: AlertLevels.ERROR,
            message: t(`myAccount:components.userDevices.notifications.${ notification }.genericError.message`)
        });
    }, [ t ]);

    const fireSuccessAlert: (notification: DeviceNotificationKey) => void = useCallback(
        (notification: DeviceNotificationKey): void => {
            onAlertFiredRef.current({
                description: t(`myAccount:components.userDevices.notifications.${ notification }.success.description`),
                level: AlertLevels.SUCCESS,
                message: t(`myAccount:components.userDevices.notifications.${ notification }.success.message`)
            });
        }, [ t ]);

    const fetchDevices: () => void = useCallback((): void => {
        getUserDevices()
            .then((response: UserDeviceListInterface) => {
                const userDevices: UserDeviceInterface[] = response?.devices ?? [];

                setDevices(userDevices);
                if (userDevices.length > 0) {
                    setHasRegisteredDevices(true);
                }
            })
            .catch((error: AxiosError<HttpErrorResponseDataInterface>) => {
                // A server without device management does not expose the API; keep the section hidden.
                if (error?.response?.status !== 404) {
                    fireErrorAlert("fetchDevices", error);
                }
            })
            .finally(() => {
                setIsLoading(false);
            });
    }, [ fireErrorAlert ]);

    useEffect(() => {
        fetchDevices();
    }, [ fetchDevices ]);

    const replaceDevice = (updatedDevice: UserDeviceInterface): void => {
        setDevices((currentDevices: UserDeviceInterface[]) => currentDevices.map(
            (device: UserDeviceInterface) => device.id === updatedDevice.id ? updatedDevice : device
        ));
    };

    const patchDevice = (
        device: UserDeviceInterface,
        patch: UserDevicePatchRequestInterface,
        notification: DeviceNotificationKey,
        onSuccess?: () => void
    ): void => {
        setPendingDeviceId(device.id);
        updateUserDevice(device.id, patch)
            .then((updatedDevice: UserDeviceInterface) => {
                replaceDevice(updatedDevice);
                fireSuccessAlert(notification);
                onSuccess?.();
            })
            .catch((error: AxiosError<HttpErrorResponseDataInterface>) => {
                fireErrorAlert(notification, error);
            })
            .finally(() => {
                setPendingDeviceId(null);
            });
    };

    const handleRename = (deviceName: string): void => {
        if (!renamingDevice) {
            return;
        }
        patchDevice(renamingDevice, { deviceName }, "renameDevice", () => setRenamingDevice(null));
    };

    const handleStatusToggle = (device: UserDeviceInterface): void => {
        const isActive: boolean = device.status === UserDeviceStatus.ACTIVE;

        patchDevice(
            device,
            { status: isActive ? UserDeviceStatus.INACTIVE : UserDeviceStatus.ACTIVE },
            isActive ? "deactivateDevice" : "activateDevice"
        );
    };

    const handleRemove = (): void => {
        if (!removingDevice) {
            return;
        }

        const deviceId: string = removingDevice.id;

        setPendingDeviceId(deviceId);
        deleteUserDevice(deviceId)
            .then(() => {
                setDevices((currentDevices: UserDeviceInterface[]) => currentDevices.filter(
                    (device: UserDeviceInterface) => device.id !== deviceId
                ));
                fireSuccessAlert("removeDevice");
            })
            .catch((error: AxiosError<HttpErrorResponseDataInterface>) => {
                fireErrorAlert("removeDevice", error);
            })
            .finally(() => {
                setPendingDeviceId(null);
                setRemovingDevice(null);
            });
    };

    const renderDevice = (device: UserDeviceInterface): ReactElement => {
        const isActive: boolean = device.status === UserDeviceStatus.ACTIVE;
        const isPending: boolean = pendingDeviceId === device.id;
        const registeredOn: string = t("myAccount:components.userDevices.registeredOn",
            { date: dayjs(device.registeredAt).fromNow() });

        return (
            <ListItem
                key={ device.id }
                divider={ true }
                data-componentid={ `${ componentId }-device-${ device.id }` }
                secondaryAction={ (
                    <DeviceActions>
                        <Chip
                            size="small"
                            color={ isActive ? "success" : "default" }
                            label={ isActive
                                ? t("myAccount:components.userDevices.status.active")
                                : t("myAccount:components.userDevices.status.inactive") }
                            data-componentid={ `${ componentId }-device-${ device.id }-status` }
                        />
                        <Tooltip title={ t("myAccount:components.userDevices.actions.rename") }>
                            <IconButton
                                aria-label={ t("myAccount:components.userDevices.actions.rename") }
                                disabled={ isPending }
                                onClick={ () => setRenamingDevice(device) }
                                data-componentid={ `${ componentId }-device-${ device.id }-rename-button` }
                            >
                                <PenToSquareIcon />
                            </IconButton>
                        </Tooltip>
                        <Tooltip title={ isActive
                            ? t("myAccount:components.userDevices.actions.deactivate")
                            : t("myAccount:components.userDevices.actions.activate") }
                        >
                            <IconButton
                                aria-label={ isActive
                                    ? t("myAccount:components.userDevices.actions.deactivate")
                                    : t("myAccount:components.userDevices.actions.activate") }
                                disabled={ isPending }
                                onClick={ () => handleStatusToggle(device) }
                                data-componentid={ `${ componentId }-device-${ device.id }-status-button` }
                            >
                                { isActive ? <BanIcon /> : <CheckIcon /> }
                            </IconButton>
                        </Tooltip>
                        <Tooltip title={ t("myAccount:components.userDevices.actions.remove") }>
                            <IconButton
                                aria-label={ t("myAccount:components.userDevices.actions.remove") }
                                color="error"
                                disabled={ isPending }
                                onClick={ () => setRemovingDevice(device) }
                                data-componentid={ `${ componentId }-device-${ device.id }-remove-button` }
                            >
                                <TrashIcon />
                            </IconButton>
                        </Tooltip>
                    </DeviceActions>
                ) }
            >
                <ListItemText
                    primary={ device.deviceName }
                    secondary={ device.deviceModel ? `${ device.deviceModel } · ${ registeredOn }` : registeredOn }
                />
            </ListItem>
        );
    };

    if (!isLoading && !hasRegisteredDevices) {
        return null;
    }

    return (
        <SettingsSection
            data-componentid={ `${ componentId }-settings-section` }
            description={ t("myAccount:sections.userDevices.description") }
            header={ t("myAccount:sections.userDevices.heading") }
        >
            { isLoading
                ? <Skeleton variant="rectangular" height={ 64 } />
                : (
                    <List data-componentid={ `${ componentId }-list` }>
                        { devices.map(renderDevice) }
                    </List>
                )
            }
            <UserDeviceRenameDialog
                device={ renamingDevice }
                isSubmitting={ Boolean(renamingDevice) && pendingDeviceId === renamingDevice?.id }
                onClose={ () => setRenamingDevice(null) }
                onSubmit={ handleRename }
                data-componentid={ `${ componentId }-rename-dialog` }
            />
            { removingDevice && (
                <ConfirmationModal
                    data-componentid={ `${ componentId }-remove-confirmation-modal` }
                    onClose={ (): void => setRemovingDevice(null) }
                    type="negative"
                    open={ Boolean(removingDevice) }
                    assertionHint={ t("myAccount:components.userDevices.modals.removeDevice.assertionHint") }
                    assertionType="checkbox"
                    primaryAction={ t("common:remove") }
                    secondaryAction={ t("common:cancel") }
                    onSecondaryActionClick={ (): void => setRemovingDevice(null) }
                    onPrimaryActionClick={ handleRemove }
                    closeOnDimmerClick={ false }
                >
                    <ConfirmationModal.Header>
                        { t("myAccount:components.userDevices.modals.removeDevice.heading") }
                    </ConfirmationModal.Header>
                    <ConfirmationModal.Message attached negative>
                        { t("myAccount:components.userDevices.modals.removeDevice.message") }
                    </ConfirmationModal.Message>
                    <ConfirmationModal.Content>
                        { t("myAccount:components.userDevices.modals.removeDevice.content") }
                    </ConfirmationModal.Content>
                </ConfirmationModal>
            ) }
        </SettingsSection>
    );
};
