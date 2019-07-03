# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ServiceFabric::V6_5_0_36
  module Models
    #
    # Describes the auto scaling policy
    #
    class AutoScalingPolicy

      include MsRestAzure

      # @return [String] The name of the auto scaling policy.
      attr_accessor :name

      # @return [AutoScalingTrigger] Determines when auto scaling operation
      # will be invoked.
      attr_accessor :trigger

      # @return [AutoScalingMechanism] The mechanism that is used to scale when
      # auto scaling operation is invoked.
      attr_accessor :mechanism


      #
      # Mapper for AutoScalingPolicy class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'AutoScalingPolicy',
          type: {
            name: 'Composite',
            class_name: 'AutoScalingPolicy',
            model_properties: {
              name: {
                client_side_validation: true,
                required: true,
                serialized_name: 'name',
                type: {
                  name: 'String'
                }
              },
              trigger: {
                client_side_validation: true,
                required: true,
                serialized_name: 'trigger',
                type: {
                  name: 'Composite',
                  polymorphic_discriminator: 'kind',
                  uber_parent: 'AutoScalingTrigger',
                  class_name: 'AutoScalingTrigger'
                }
              },
              mechanism: {
                client_side_validation: true,
                required: true,
                serialized_name: 'mechanism',
                type: {
                  name: 'Composite',
                  polymorphic_discriminator: 'kind',
                  uber_parent: 'AutoScalingMechanism',
                  class_name: 'AutoScalingMechanism'
                }
              }
            }
          }
        }
      end
    end
  end
end
