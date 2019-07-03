# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ServiceFabric::V6_5_0_36
  module Models
    #
    # A ServiceUpdateDescription contains all of the information necessary to
    # update a service.
    #
    class ServiceUpdateDescription

      include MsRestAzure

      @@discriminatorMap = Hash.new
      @@discriminatorMap["Stateful"] = "StatefulServiceUpdateDescription"
      @@discriminatorMap["Stateless"] = "StatelessServiceUpdateDescription"

      def initialize
        @ServiceKind = "ServiceUpdateDescription"
      end

      attr_accessor :ServiceKind

      # @return [String] Flags indicating whether other properties are set.
      # Each of the associated properties corresponds to a flag, specified
      # below, which, if set, indicate that the property is specified.
      # This property can be a combination of those flags obtained using
      # bitwise 'OR' operator.
      # For example, if the provided value is 6 then the flags for
      # ReplicaRestartWaitDuration (2) and QuorumLossWaitDuration (4) are set.
      #
      # - None - Does not indicate any other properties are set. The value is
      # zero.
      # - TargetReplicaSetSize/InstanceCount - Indicates whether the
      # TargetReplicaSetSize property (for Stateful services) or the
      # InstanceCount property (for Stateless services) is set. The value is 1.
      # - ReplicaRestartWaitDuration - Indicates the ReplicaRestartWaitDuration
      # property is set. The value is  2.
      # - QuorumLossWaitDuration - Indicates the QuorumLossWaitDuration
      # property is set. The value is 4.
      # - StandByReplicaKeepDuration - Indicates the StandByReplicaKeepDuration
      # property is set. The value is 8.
      # - MinReplicaSetSize - Indicates the MinReplicaSetSize property is set.
      # The value is 16.
      # - PlacementConstraints - Indicates the PlacementConstraints property is
      # set. The value is 32.
      # - PlacementPolicyList - Indicates the ServicePlacementPolicies property
      # is set. The value is 64.
      # - Correlation - Indicates the CorrelationScheme property is set. The
      # value is 128.
      # - Metrics - Indicates the ServiceLoadMetrics property is set. The value
      # is 256.
      # - DefaultMoveCost - Indicates the DefaultMoveCost property is set. The
      # value is 512.
      # - ScalingPolicy - Indicates the ScalingPolicies property is set. The
      # value is 1024.
      attr_accessor :flags

      # @return [String] The placement constraints as a string. Placement
      # constraints are boolean expressions on node properties and allow for
      # restricting a service to particular nodes based on the service
      # requirements. For example, to place a service on nodes where NodeType
      # is blue specify the following: "NodeColor == blue)".
      attr_accessor :placement_constraints

      # @return [Array<ServiceCorrelationDescription>] The correlation scheme.
      attr_accessor :correlation_scheme

      # @return [Array<ServiceLoadMetricDescription>] The service load metrics.
      attr_accessor :load_metrics

      # @return [Array<ServicePlacementPolicyDescription>] The service
      # placement policies.
      attr_accessor :service_placement_policies

      # @return [MoveCost] The move cost for the service. Possible values
      # include: 'Zero', 'Low', 'Medium', 'High'
      attr_accessor :default_move_cost

      # @return [Array<ScalingPolicyDescription>] Scaling policies for this
      # service.
      attr_accessor :scaling_policies


      #
      # Mapper for ServiceUpdateDescription class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ServiceUpdateDescription',
          type: {
            name: 'Composite',
            polymorphic_discriminator: 'ServiceKind',
            uber_parent: 'ServiceUpdateDescription',
            class_name: 'ServiceUpdateDescription',
            model_properties: {
              flags: {
                client_side_validation: true,
                required: false,
                serialized_name: 'Flags',
                type: {
                  name: 'String'
                }
              },
              placement_constraints: {
                client_side_validation: true,
                required: false,
                serialized_name: 'PlacementConstraints',
                type: {
                  name: 'String'
                }
              },
              correlation_scheme: {
                client_side_validation: true,
                required: false,
                serialized_name: 'CorrelationScheme',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'ServiceCorrelationDescriptionElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'ServiceCorrelationDescription'
                      }
                  }
                }
              },
              load_metrics: {
                client_side_validation: true,
                required: false,
                serialized_name: 'LoadMetrics',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'ServiceLoadMetricDescriptionElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'ServiceLoadMetricDescription'
                      }
                  }
                }
              },
              service_placement_policies: {
                client_side_validation: true,
                required: false,
                serialized_name: 'ServicePlacementPolicies',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'ServicePlacementPolicyDescriptionElementType',
                      type: {
                        name: 'Composite',
                        polymorphic_discriminator: 'Type',
                        uber_parent: 'ServicePlacementPolicyDescription',
                        class_name: 'ServicePlacementPolicyDescription'
                      }
                  }
                }
              },
              default_move_cost: {
                client_side_validation: true,
                required: false,
                serialized_name: 'DefaultMoveCost',
                type: {
                  name: 'String'
                }
              },
              scaling_policies: {
                client_side_validation: true,
                required: false,
                serialized_name: 'ScalingPolicies',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'ScalingPolicyDescriptionElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'ScalingPolicyDescription'
                      }
                  }
                }
              }
            }
          }
        }
      end
    end
  end
end
