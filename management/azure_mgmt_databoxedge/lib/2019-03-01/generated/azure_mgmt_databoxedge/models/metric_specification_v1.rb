# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::DataBoxEdge::Mgmt::V2019_03_01
  module Models
    #
    # Metric specification version 1.
    #
    class MetricSpecificationV1

      include MsRestAzure

      # @return [String] Name of the metric.
      attr_accessor :name

      # @return [String] Display name of the metric.
      attr_accessor :display_name

      # @return [String] Description of the metric to be displayed.
      attr_accessor :display_description

      # @return [MetricUnit] Metric units. Possible values include:
      # 'NotSpecified', 'Percent', 'Count', 'Seconds', 'Milliseconds', 'Bytes',
      # 'BytesPerSecond', 'CountPerSecond'
      attr_accessor :unit

      # @return [MetricAggregationType] Metric aggregation type. Possible
      # values include: 'NotSpecified', 'None', 'Average', 'Minimum',
      # 'Maximum', 'Total', 'Count'
      attr_accessor :aggregation_type

      # @return [Array<MetricDimensionV1>] Metric dimensions, other than
      # default dimension which is resource.
      attr_accessor :dimensions

      # @return [Boolean] Set true to fill the gaps with zero.
      attr_accessor :fill_gap_with_zero

      # @return [MetricCategory] Metric category. Possible values include:
      # 'Capacity', 'Transaction'
      attr_accessor :category

      # @return [String] Resource name override.
      attr_accessor :resource_id_dimension_name_override

      # @return [Array<TimeGrain>] Support granularity of metrics.
      attr_accessor :supported_time_grain_types

      # @return [Array<MetricAggregationType>] Support metric aggregation type.
      attr_accessor :supported_aggregation_types


      #
      # Mapper for MetricSpecificationV1 class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'MetricSpecification_V1',
          type: {
            name: 'Composite',
            class_name: 'MetricSpecificationV1',
            model_properties: {
              name: {
                client_side_validation: true,
                required: false,
                serialized_name: 'name',
                type: {
                  name: 'String'
                }
              },
              display_name: {
                client_side_validation: true,
                required: false,
                serialized_name: 'displayName',
                type: {
                  name: 'String'
                }
              },
              display_description: {
                client_side_validation: true,
                required: false,
                serialized_name: 'displayDescription',
                type: {
                  name: 'String'
                }
              },
              unit: {
                client_side_validation: true,
                required: false,
                serialized_name: 'unit',
                type: {
                  name: 'String'
                }
              },
              aggregation_type: {
                client_side_validation: true,
                required: false,
                serialized_name: 'aggregationType',
                type: {
                  name: 'String'
                }
              },
              dimensions: {
                client_side_validation: true,
                required: false,
                serialized_name: 'dimensions',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'MetricDimensionV1ElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'MetricDimensionV1'
                      }
                  }
                }
              },
              fill_gap_with_zero: {
                client_side_validation: true,
                required: false,
                serialized_name: 'fillGapWithZero',
                type: {
                  name: 'Boolean'
                }
              },
              category: {
                client_side_validation: true,
                required: false,
                serialized_name: 'category',
                type: {
                  name: 'String'
                }
              },
              resource_id_dimension_name_override: {
                client_side_validation: true,
                required: false,
                serialized_name: 'resourceIdDimensionNameOverride',
                type: {
                  name: 'String'
                }
              },
              supported_time_grain_types: {
                client_side_validation: true,
                required: false,
                serialized_name: 'supportedTimeGrainTypes',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'TimeGrainElementType',
                      type: {
                        name: 'String'
                      }
                  }
                }
              },
              supported_aggregation_types: {
                client_side_validation: true,
                required: false,
                serialized_name: 'supportedAggregationTypes',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'MetricAggregationTypeElementType',
                      type: {
                        name: 'String'
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
