/**
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

import * as React from "react";
import { Button, Container, Form, Transition } from "semantic-ui-react";
import { updatePassword } from "../actions/profile";
import { NotificationComponent } from "../components";
import { InnerPageLayout } from "../layouts";

interface State {
    currentPassword: string;
    newPassword: string;
    confirmPassword: string;
    currentPasswordError: boolean;
    newPasswordError: boolean;
    confirmPasswordError: boolean;
    notification: NotifcationStateInterface;
}
interface Props {}
interface NotifcationStateInterface {
    visible: boolean;
    message: string;
    description: string;
    otherProps: object;
}

export class ChangePasswordPage extends React.Component<Props, State> {
    public state = {
        currentPassword: "",
        newPassword: "",
        confirmPassword: "",
        currentPasswordError: false,
        newPasswordError: false,
        confirmPasswordError: false,
        notification: {
            visible: false,
            message: "",
            description: "",
            otherProps: {}
        }
    };

    public handleInputChange = (
        e: React.ChangeEvent<HTMLInputElement>,
        { name, value }: { name: string; value: string }
    ) => {
        // `as Pick<State, keyof State>` was used to silent the linter warning
        this.setState({ [name]: value } as Pick<State, "currentPassword" | "newPassword" | "confirmPassword">);
    }

    public handleSubmit = () => {
        const { currentPassword, newPassword, confirmPassword, notification } = this.state;

        const hasErrors = this.validateInputs(currentPassword, newPassword, confirmPassword);

        // If the form has errors, return from the function.
        if (hasErrors) {
            return;
        }

        // Check if the new password matches the confirmation field.
        // If there's a mismatch, clears the text fields and return.
        if (newPassword !== confirmPassword) {
            this.setState(({
                notification: {
                    ...notification,
                    visible: true,
                    message: "Password reset error",
                    description: "The password confirmation doesn't match the new password",
                    otherProps: {
                        negative: true
                    }
                },
                newPassword: "",
                confirmPassword: ""
            } as unknown) as Pick<State, "notification">);

            return;
        }

        updatePassword(currentPassword, newPassword)
            .then((response) => {
                if (response.status && response.status === 200) {
                    this.setState(({
                        notification: {
                            ...notification,
                            visible: true,
                            message: "Password reset successful",
                            description: "The password has been changed successfully",
                            otherProps: {
                                positive: true
                            }
                        }
                    } as unknown) as Pick<State, "notification">);
                }
            })
            .catch((error) => {
                // Axios throws a generic `Network Error` for 401 status.
                // As a temporary solution, a check to see if a response
                // is available has be used.
                if (!error.response || error.response.status === 401) {
                    this.setState(({
                        notification: {
                            ...notification,
                            visible: true,
                            message: "Password reset error",
                            description: "The current password you entered appears to be invalid. Please try again",
                            otherProps: {
                                negative: true
                            }
                        }
                    } as unknown) as Pick<State, "notification">);
                } else if (error.response && error.response.data && error.response.data.detail) {
                    this.setState(({
                        notification: {
                            ...notification,
                            visible: true,
                            message: "Password reset error",
                            description: error.response.data.detail,
                            otherProps: {
                                negative: true
                            }
                        }
                    } as unknown) as Pick<State, "notification">);
                } else {
                    // Generic error message
                    this.setState(({
                        notification: {
                            ...notification,
                            visible: true,
                            message: "Password reset error",
                            description: "Something went wrong. Please try again.",
                            otherProps: {
                                negative: true
                            }
                        }
                    } as unknown) as Pick<State, "notification">);
                }
            });
    }

    public validateInputs = (currentPassword, newPassword, confirmPassword) => {
        let hasErrors = false;

        if (currentPassword === null || currentPassword === "") {
            hasErrors = true;
            this.setState({ currentPasswordError: true } as Pick<State, "currentPasswordError">);
        } else {
            this.setState({ currentPasswordError: false } as Pick<State, "currentPasswordError">);
        }

        if (newPassword === null || newPassword === "") {
            hasErrors = true;
            this.setState({ newPasswordError: true } as Pick<State, "newPasswordError">);
        } else {
            this.setState({ newPasswordError: false } as Pick<State, "newPasswordError">);
        }

        if (confirmPassword === null || confirmPassword === "") {
            hasErrors = true;
            this.setState({ confirmPasswordError: true } as Pick<State, "confirmPasswordError">);
        } else {
            this.setState({ confirmPasswordError: false } as Pick<State, "confirmPasswordError">);
        }

        return hasErrors;
    }

    public handleNotificationDismiss = () => {
        const { notification } = this.state;
        this.setState(({
            notification: {
                ...notification,
                visible: false
            }
        } as unknown) as Pick<State, "notification">);
    }

    public render() {
        const {
            currentPassword,
            newPassword,
            confirmPassword,
            currentPasswordError,
            newPasswordError,
            confirmPasswordError,
            notification
        } = this.state;
        const { visible, message, description, otherProps } = notification;
        return (
            <InnerPageLayout pageTitle="Change Password" pageDescription="Change and modify the existing password">
                <Container>
                    <Transition visible={visible} animation="fade" duration={500}>
                        <NotificationComponent
                            message={message}
                            description={description}
                            onDismiss={this.handleNotificationDismiss}
                            {...otherProps}
                        />
                    </Transition>

                    <Form onSubmit={this.handleSubmit}>
                        <Form.Input
                            name="currentPassword"
                            label="Current password"
                            placeholder="Current password"
                            type="password"
                            value={currentPassword}
                            onChange={this.handleInputChange}
                            error={currentPasswordError ? { content: "Current pasword is required" } : false}
                        />
                        <Form.Input
                            name="newPassword"
                            label="New password"
                            placeholder="New password"
                            type="password"
                            value={newPassword}
                            onChange={this.handleInputChange}
                            error={newPasswordError ? { content: "New pasword is required" } : false}
                        />
                        <Form.Input
                            name="confirmPassword"
                            label="Confirm new password"
                            placeholder="Confirm new password"
                            type="password"
                            value={confirmPassword}
                            onChange={this.handleInputChange}
                            error={confirmPasswordError ? { content: "Confirm pasword is required" } : false}
                        />
                        <br />
                        <Button primary type="submit">
                            Submit
                        </Button>
                    </Form>
                </Container>
            </InnerPageLayout>
        );
    }
}
