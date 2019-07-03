# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ContainerRegistry::Mgmt::V2019_06_01_preview
  module Models
    #
    # The properties for updating a timer trigger.
    #
    class TimerTriggerUpdateParameters

      include MsRestAzure

      # @return [String] The CRON expression for the task schedule
      attr_accessor :schedule

      # @return [TriggerStatus] The current status of trigger. Possible values
      # include: 'Disabled', 'Enabled'. Default value: 'Enabled' .
      attr_accessor :status

      # @return [String] The name of the trigger.
      attr_accessor :name


      #
      # Mapper for TimerTriggerUpdateParameters class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'TimerTriggerUpdateParameters',
          type: {
            name: 'Composite',
            class_name: 'TimerTriggerUpdateParameters',
            model_properties: {
              schedule: {
                client_side_validation: true,
                required: false,
                serialized_name: 'schedule',
                type: {
                  name: 'String'
                }
              },
              status: {
                client_side_validation: true,
                required: false,
                serialized_name: 'status',
                default_value: 'Enabled',
                type: {
                  name: 'String'
                }
              },
              name: {
                client_side_validation: true,
                required: true,
                serialized_name: 'name',
                type: {
                  name: 'String'
                }
              }
            }
          }
        }
      end
    end
  end
end
